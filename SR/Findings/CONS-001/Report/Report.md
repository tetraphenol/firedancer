## The Bug

The tower tile's pre-execution vote counting function (`count_vote_txn`) accepts vote transactions without verifying that the transaction signer is the authorized voter for the referenced vote account. An attacker with any Ed25519 keypair can craft TowerSync transactions that attribute arbitrary staked validators' stake to attacker-chosen block IDs in the target validator's fork choice tracking. Real votes for the same slot are permanently blocked by the `ALREADY_VOTED` deduplication guard.

When sustained against a block-producing validator, this causes the validator to skip its leader slots - matching the Medium impact: "the validator fails to produce blocks during its assigned leader slots."

## Vulnerability Details

**Location:** `src/discof/tower/fd_tower_tile.c:745-746`

`count_vote_txn` processes pre-execution vote transactions arriving via the TPU path (QUIC -> verify -> dedup -> tower). At lines 745-746, the code explicitly acknowledges the missing check:

```
/* TODO check the authorized voter for this vote account (from epoch
   stakes) is one of the signers. */
```

The function validates that the vote account is staked (line 814-816 via `stk_vtr_map` lookup) but never verifies that any signer on the transaction is the authorized voter for that vote account.

**Attack vector:**

1. Attacker crafts a legacy transaction with 1 signature (their own key)
2. Account list: `[attacker_pubkey (signer), victim_vote_account, Vote111...111 (program ID)]`
3. Instruction data: TowerSync with votes for an attacker-chosen slot/block_id
4. Transaction is submitted via QUIC to the target validator's TPU port
5. Passes ED25519 verification (valid signature from attacker's key)
6. Passes `fd_txn_is_simple_vote_transaction` (fd_txn.h:456-471: 1 instruction, legacy, <=2 sigs, vote program ID match)
7. Tower tile extracts `vote_acc = accs[1]` (line 792) without checking that `accs[0]` (the signer) is authorized to vote for it
8. Vote is counted with the victim's full stake toward the attacker's chosen block_id (`fd_votes_count_vote` at line 824, `fd_hfork_count_vote` at line 821)
9. When the real vote for the same slot arrives later, `fd_votes_count_vote` returns `FD_VOTES_ERR_ALREADY_VOTED` (fd_votes.c:353) - the real vote is silently dropped

**Data flow:**

- Topology: QUIC -> verify -> dedup -> tower (topology.c:941, `dedup_resolv` link, when `leader_enabled`)
- `leader_enabled = !!config->firedancer.layout.enable_block_production` (topology.c:390) - true for any block-producing validator, not just the current leader

**Exploitability:**

- Attacker needs: any valid Ed25519 keypair, list of staked vote account pubkeys (public on-chain data), current slot numbers (public)
- Attacker does NOT need: validator identity, any stake, the victim's vote authority key
- Network access: QUIC TPU port (publicly accessible by design; stake-weighted QoS does not block unstaked senders at this low transaction volume)
- Rate: one transaction per victim vote account per slot

**Key deduplication asymmetry:**

- `fd_votes_count_vote` deduplicates by `(vote_acc, slot)` - a fake vote for slot X blocks the real vote for slot X regardless of block_id
- `fd_hfork_count_vote` deduplicates by `(vote_acc, block_id)` - a fake vote for block_id_A does NOT block the real vote for block_id_B

The most severe impact path (duplicate confirmation -> `fd_ghost_eqvoc`) flows through `fd_votes`, where the dedup is most effective for the attacker.

**Architectural difference from Agave:**

Agave's `cluster_info_vote_listener` only processes gossip votes (CRDS-signed by validator identity). Firedancer's tower tile also processes raw TPU transactions via `IN_KIND_DEDUP`, which have no identity verification beyond the ED25519 signature check.

## Exploitation

The attacker can submit fake votes preemptively for future slots before real validators have even seen the block, because:

1. `fd_votes` dedup is slot-keyed and block_id-agnostic - the attacker does not need to know the real block_id
2. Real validators can only vote after replaying a block (hundreds of milliseconds of latency)
3. The attacker can cover the entire vote window (~512 upcoming slots) in a single burst

This eliminates any meaningful race condition with honest voters.

**Vote displacement (basic attack):**

For each target slot, the attacker sends one fake vote per victim vote account. Each fake vote permanently occupies the `(vote_acc, slot)` entry in `fd_votes`, blocking the real vote.

**Ghost tree invalidation (escalated attack):**

If the attacker targets enough validators' vote accounts to accumulate >52% of total stake for a non-existent block_id at a given slot, `publish_slot_confirmed` (line 534-538) triggers `fd_ghost_eqvoc` on the honest replayed block. This marks the honest block and its entire subtree as invalid in the ghost fork choice tree.

`fd_ghost_best` (used by `fd_tower_vote_and_reset` for fork selection) only follows valid children. With the honest block invalidated, the target validator rolls back to an ancestor (Case 1a in `fd_tower_vote_and_reset`: ancestor rollback) and skips its leader slots.

**Sustained attack:**

By continuously submitting fake votes for upcoming slots, the attacker keeps the ghost tree corrupted at the frontier. Every new honest block gets marked as equivocating. The target validator cannot advance fork choice and skips all its leader slots.

Bandwidth requirement: ~1040 transactions per target per slot (~200 bytes each, at ~400ms per slot). This is well within the capacity of a single host targeting a single validator.

**Safety boundary:**

The attack cannot escalate beyond fork choice disruption (liveness) to finalization corruption (safety):

- Fork selection is not finalization. `fd_tower_vote_and_reset` (line 677) accepts `votes` as `FD_PARAM_UNUSED`. Root advancement is determined by `push_vote` (fd_tower.c:287), which is pure lockout arithmetic on the validator's own tower. Ghost validity plays no role in rooting.
- Ghost can only be subtracted from, not added to. The attacker can invalidate honest blocks via `fd_ghost_eqvoc`, but cannot insert new blocks. Blocks only enter ghost when received via turbine and replayed.
- Pre-execution and replay paths update different structures. `count_vote_txn` updates `fd_votes` and `fd_hfork`. `count_vote_acc` (replay path, line 678-715) updates `fd_tower_count_vote` and `fd_ghost_count_vote`. Only the replay path contributes to the lockout progression that determines finalization.

## Impact

The attack causes the target Firedancer validator to skip its assigned leader slots.

- Any block-producing Firedancer validator with an accessible QUIC TPU port is vulnerable
- The attack can be sustained indefinitely at low cost (no stake, no fees, minimal bandwidth)
- Multiple validators can be targeted simultaneously
- Recovery occurs when the attacker stops and the tower root advances past the poisoned slots

This matches the Medium in-scope impact: **"Leader slot skipping - the validator fails to produce blocks during its assigned leader slots."**

## Proof of Concept

A unit test has been added to the existing tower tile test harness (`src/discof/tower/test_tower_tile.c`) as `test_vote_poisoning_auth_voter_bypass`. It builds against the v1.0 branch with no external dependencies beyond `liblz4-dev`.

The test:

1. Initializes a complete choreo context (ghost, tower, hfork, votes) using the existing fixture data via `eqvoc_setup`
2. Registers a victim vote account (`0xBEEF`) as staked in `stk_vtr_map`, the `votes` voter registry, and sets `ghost_root->total_stake`
3. Builds a 1-sig TowerSync transaction with `attacker_key` (`0xBAD1`) as signer and `victim_vote_acc` (`0xBEEF`) as accounts[1]
4. Calls `count_vote_txn` - the fake vote is accepted (no error metrics, `votes_already_voted == 0`)
5. Builds the same transaction with `victim_auth_key` (`0x5AFE`, the real authorized voter) as signer for the same slot
6. Calls `count_vote_txn` - the real vote is rejected (`votes_already_voted == 1`)

### Build and run

Tested on Ubuntu 22.04 (amd64). Requires GCC, make, and liblz4-dev.

```bash
cd firedancer
git checkout v1.0

# Apply the PoC patch
git apply vote_poisoning_poc.patch

# Install lz4 (if not already present) and configure for build
sudo apt install -y liblz4-dev
mkdir -p opt/lib opt/include
ln -sf /usr/lib/x86_64-linux-gnu/liblz4.a opt/lib/liblz4.a
for h in lz4.h lz4frame.h lz4frame_static.h lz4hc.h; do
  ln -sf /usr/include/$h opt/include/$h
done

# Build
make -j$(nproc) build/native/gcc/unit-test/test_tower_tile

# Configure hugepages and run
sudo sysctl -w vm.nr_hugepages=2048
sudo ./build/native/gcc/unit-test/test_tower_tile --log-level-stderr NOTICE
```

Note: the test uses 2 MiB hugepages (`"huge"`) rather than 1 GiB gigantic pages. Systems with gigantic page support can revert the page size change in `main()` (4 gigantic pages = 4 GiB).

### Expected output

```
NOTICE  pass: test_count_vote_txn_tower_checks
NOTICE  pass: test_fixture_replay
NOTICE  pass: test_eqvoc_rce_same
NOTICE  pass: test_eqvoc_rec_same
NOTICE  pass: test_eqvoc_cre_same
NOTICE  pass: test_eqvoc_rce_diff
NOTICE  pass: test_eqvoc_erc_diff
NOTICE  pass: test_eqvoc_cre_diff
NOTICE  PASS: vote-poisoning - attacker_key=0000bad1 voted for victim_vote_acc=0000beef at slot 398915654; real vote by victim_auth_key=00005afe rejected ALREADY_VOTED
```

The final line confirms: a vote signed by an unrelated attacker key (`0xBAD1`) was accepted for the victim's vote account (`0xBEEF`), and the real authorized voter's (`0x5AFE`) subsequent vote for the same slot was permanently rejected with `ALREADY_VOTED`.

### PoC files

- `vote_poisoning_poc.patch` - patch against v1.0 `test_tower_tile.c`
- `test_tower_tile.c` - full modified test file (for reference)

## Root Cause and Suggested Fix

Add an authorized voter check at lines 745-746 of `fd_tower_tile.c`, using the epoch stakes to verify that at least one transaction signer matches the authorized voter for the referenced vote account:

```c
/* After extracting vote_acc at line 792, before the stk_vtr_map lookup: */

fd_tower_stakes_vtr_xid_t xid = { .addr = *vote_acc, .slot = ctx->tower->root };
fd_tower_stakes_vtr_t *   vtr = fd_tower_stakes_vtr_map_ele_query(
    ctx->tower->stk_vtr_map, &xid, NULL, ctx->tower->stk_vtr_pool );
if( FD_UNLIKELY( !vtr ) ) return;

/* Check that at least one signer is the authorized voter for this
   vote account.  The authorized voter pubkey should be stored in or
   derivable from the epoch stakes data. */

int authorized = 0;
for( ulong i = 0; i < txn->signature_cnt; i++ ) {
  fd_pubkey_t const * signer = &accs[i];
  if( 0==memcmp( signer, &vtr->authorized_voter, sizeof(fd_pubkey_t) ) ) {
    authorized = 1;
    break;
  }
}
if( FD_UNLIKELY( !authorized ) ) return;
```

This requires storing the authorized voter pubkey in the `fd_tower_stakes_vtr_t` structure (or looking it up from epoch stakes). The authorized voter for each vote account is available from the on-chain vote account state and is already read during epoch boundary processing.
