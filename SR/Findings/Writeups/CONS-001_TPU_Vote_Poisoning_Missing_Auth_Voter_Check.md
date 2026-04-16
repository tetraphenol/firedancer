# CONS-001: Pre-Execution Vote Poisoning via Missing Authorized Voter Check

## Severity
MEDIUM (Leader slot skipping / invalid block production via fork choice manipulation)

## Summary
The tower tile's `count_vote_txn` function counts vote transactions from the dedup tile (pre-execution TPU path) without verifying that the transaction signer is the authorized voter for the referenced vote account. An attacker can craft vote transactions signed by their own key that reference any staked validator's vote account, causing the victim validator's stake to be attributed to an attacker-chosen block_id in fork choice tracking. Once counted in `fd_votes`, the fake vote preempts the real vote (via `ALREADY_VOTED` dedup), poisoning that slot's fork choice state.

## Vulnerability Details

**Location:** `src/discof/tower/fd_tower_tile.c:745-746`

**Root Cause:**
`count_vote_txn` processes pre-execution vote transactions and explicitly acknowledges the missing check:
```
/* TODO check the authorized voter for this vote account (from epoch
   stakes) is one of the signers. */
```

The function validates that the vote account is staked (line 814-816 via `stk_vtr_map` lookup) but never verifies that ANY signer on the transaction is the authorized voter for that vote account.

**Attack Vector:**
1. Attacker crafts a legacy transaction with 1 signature (their own key)
2. Account list: [attacker_pubkey (signer), victim_vote_account, Vote111...111 (program ID)]
3. Instruction data: TowerSync with votes for an attacker-chosen slot/block_id
4. Transaction is submitted via QUIC to the target validator
5. Passes ED25519 verification (valid signature from attacker's key)
6. Passes `fd_txn_is_simple_vote_transaction` (fd_txn.h:456-471: 1 instruction, legacy, <=2 sigs, vote program ID match)
7. Tower tile counts the vote with the victim's full stake toward the attacker's chosen block_id (`fd_votes_count_vote` at line 824, `fd_hfork_count_vote` at line 821)
8. When the real vote for the same slot arrives later, `fd_votes_count_vote` returns `FD_VOTES_ERR_ALREADY_VOTED` (fd_votes.c:353) - the real vote is silently dropped

**Data flow:**
- Topology: QUIC -> verify -> dedup -> tower (topology.c:941, `dedup_resolv` link, when `leader_enabled`)
- `leader_enabled = !!config->firedancer.layout.enable_block_production` (topology.c:390) - true for block-producing validators

**Exploitability:**
- Attacker needs: any valid Ed25519 keypair, list of staked vote account pubkeys (public on-chain data), current slot numbers (public)
- Attacker does NOT need: validator identity, any stake, the victim's vote authority key
- Rate: one transaction per victim vote account per slot
- Network access: QUIC TPU port (publicly accessible by design; stake-weighted QoS does not block unstaked senders at this low volume)
- Timing: attacker can preemptively submit for future slots (before the real block exists) because `fd_votes` dedup is slot-keyed and block_id-agnostic. The attacker does not need to know the real block_id - any value works. This eliminates any meaningful race condition with honest voters, who must wait until the block is replayed before voting.
- Batch capability: a single burst can cover the entire vote window (~512 upcoming slots) for all ~2000 staked validators

**fd_votes vs fd_hfork dedup difference:**
- `fd_votes_count_vote` deduplicates by (vote_acc, slot) - fake vote for slot X blocks the real vote for slot X regardless of block_id
- `fd_hfork_count_vote` deduplicates by (vote_acc, block_id) - fake vote for block_id_A does NOT block the real vote for block_id_B
- The most severe impact (duplicate confirmation -> `fd_ghost_eqvoc`) flows through `fd_votes`, where the dedup is most effective for the attacker

## Impact

**Liveness impact (confirmed):**

- **Vote preemption:** The `ALREADY_VOTED` guard in `fd_votes_count_vote` (fd_votes.c:353) means fake votes permanently displace real votes for the same slot. There is no mechanism to "uncount" a fake vote.
- **Ghost tree invalidation:** If fake votes for a non-existent block_id accumulate past the `FD_TOWER_SLOT_CONFIRMED_DUPLICATE` threshold (52% stake), `publish_slot_confirmed` (line 534-538) calls `fd_ghost_eqvoc` on the honest replayed block. This marks the honest block and its entire subtree as invalid via `mark_invalid` (fd_ghost.c:541). `fd_ghost_best` (used by `fd_tower_vote_and_reset` for fork selection) only follows valid children, so the target validator rolls back to an ancestor (Case 1a: ancestor rollback).
- **Leader slot skipping:** A validator whose fork choice is disrupted will skip its own leader slots if it cannot build on its current fork.
- **Practical outcome:** Matches MEDIUM impact: "Any bug leading Firedancer v1.0 to produce an invalid block or skip its leader slot"

**Safety boundary (why this cannot escalate to fund theft or consensus failure):**

- **Fork selection is not finalization.** `fd_tower_vote_and_reset` (line 677) accepts `votes` as `FD_PARAM_UNUSED`. Root advancement is determined by `push_vote` (fd_tower.c:287), which is pure lockout arithmetic on the validator's own tower (31 consecutive confirmations). Ghost validity state plays no role in rooting.
- **Ghost can only be subtracted from, not added to.** The attacker can invalidate honest blocks via `fd_ghost_eqvoc`, but cannot insert new blocks. Blocks only enter ghost when received via turbine and replayed. There is no code path from `count_vote_txn` to `fd_ghost_insert`.
- **Pre-execution and replay paths update different structures.** `count_vote_txn` updates `fd_votes` and `fd_hfork`. `count_vote_acc` (replay path, line 678-715) updates `fd_tower_count_vote` and `fd_ghost_count_vote`. They do not interfere, but critically, only the replay path contributes to the lockout progression that determines finalization.
- **Transaction execution is deterministic.** All validators independently execute blocks and compute bank hashes. A leader cannot forge state transitions (e.g., unauthorized transfers) because Solana transactions require valid Ed25519 signatures from account owners.

## Contest Scope Assessment

- **Attacker model:** Remote attacker with no pre-existing validator access - matches contest requirement
- **Impact category:** MEDIUM - "Any bug leading Firedancer v1.0 to produce an invalid block or skip its leader slot." Does not reach HIGH ("consensus failure among the majority of the network") because the pre-execution vote path is advisory - finalization is controlled by the replay/execution path and tower lockout progression, which are not affected.
- **Not excluded by known issues:** #9157 (consensus) covers float arithmetic, stale fields, dead code - not vote authentication. #9171 item 8 (vote misclassification) is in Frankendancer-only `fd_bank_abi.c`, not the tower tile.
- **Code verified present:** TODO at lines 745 and 750 confirmed on latest v1.0 (commit 920d83054)
- **Agave architectural difference:** Agave's `cluster_info_vote_listener` only processes gossip votes (CRDS-signed by validator identity). Firedancer's tower tile also processes raw TPU transactions via `IN_KIND_DEDUP`, which have no identity verification beyond ED25519 signature check.

## Proof of Concept

A unit-level PoC has been added to `src/discof/tower/test_tower_tile.c` as `test_cons_001_auth_voter_bypass`. It builds directly on the existing test harness (no full validator required).

**Setup:**
1. Calls `eqvoc_setup(wksp)` to initialize a complete choreo context (ghost, tower, hfork, votes) using existing fixture data.
2. Registers `victim_vote_acc` in `stk_vtr_map`, `votes` voter registry, and sets `ghost_root->total_stake`.

**Execution:**
1. Builds a 1-sig TowerSync transaction with `attacker_key` as signer and `victim_vote_acc` as accounts[1].
2. Calls `count_vote_txn` - accepted with no error metrics (`votes_already_voted == 0`).
3. Builds the same transaction with `victim_auth_key` as signer (the real authorized voter) for the same slot.
4. Calls `count_vote_txn` - rejected with `votes_already_voted == 1`.

**Build and run:**
```
cd /home/user/FiredancerAC/firedancer
sudo sysctl -w vm.nr_hugepages=2048
make -j build/native/gcc/unit-test/test_tower_tile
sudo ./build/native/gcc/unit-test/test_tower_tile --log-level-stderr NOTICE
```

**Expected output:**
```
PASS: CONS-001 - attacker_key=0000bad1 voted for victim_vote_acc=0000beef
at slot 398915654; real vote by victim_auth_key=00005afe rejected ALREADY_VOTED
```

## Notes

- The `IN_KIND_REPLAY` path (line 1503-1507) correctly only counts executed votes - the issue is exclusively in the dedup (pre-execution) path.
- The second TODO at line 750 (`TODO SECURITY ensure SIMD-0138 is activated`) suggests additional protocol-level concerns.
- The fake vote transaction will eventually be executed by the vote program and rejected (wrong authorized voter), but the tower tile has already counted it and will not uncount it.
