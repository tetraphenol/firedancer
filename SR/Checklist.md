# Security Audit Checklist: Firedancer v1.0

**Program:** Immunefi Audit Contest - Firedancer v1.0
**Scope:** `firedancer` binary and all reachable code (branch: v1.0)
**Date:** April 9, 2026
**Attacker Model:** Remote-only; no pre-existing validator access

> **Note on exclusions:** Items covered by known issues #9154, #9157, #9159-9162, #9164-9166,
> #9168, #9170-9173, #9175-9178 are omitted throughout. Items referencing those files may
> still appear when checking distinct, non-excluded aspects.

---

## Table of Contents

0B. [Fuzzing-Guided Targeted Review](#0b-fuzzing-guided-targeted-review) 🔴
0C. [Advanced Attack Vectors (Round 2)](#0c-advanced-attack-vectors-round-2) 🔴
1. [QUIC / Network Layer](#1-quic--network-layer) 🔴
2. [TLS 1.3 Implementation](#2-tls-13-implementation) 🔴
3. [Gossip Protocol](#3-gossip-protocol) 🔴
4. [Transaction Processing Pipeline](#4-transaction-processing-pipeline) 🟣
5. [sBPF VM - Core Execution](#5-sbpf-vm---core-execution) 🟣
6. [sBPF VM - Syscalls and CPI](#6-sbpf-vm---syscalls-and-cpi) 🟣
7. [ELF / sBPF Loader](#7-elf--sbpf-loader) 🟣
8. [Runtime - Built-in Programs](#8-runtime---built-in-programs) 🟣
9. [Runtime Conformance (vs. Agave)](#9-runtime-conformance-vs-agave) 🟣
10. [Proof of History](#10-proof-of-history) 🔴
11. [Shred Tile & FEC Resolver](#11-shred-tile--fec-resolver) 🔴
12. [Shred Reassembly (Reasm)](#12-shred-reassembly-reasm) 🔴
13. [Consensus - Tower BFT](#13-consensus---tower-bft) 🔴
14. [Consensus - Ghost Fork Choice](#14-consensus---ghost-fork-choice) 🔴
15. [Consensus - Equivocation Detection](#15-consensus---equivocation-detection) 🔴
16. [Replay Tile](#16-replay-tile) 🟣
17. [Repair Protocol](#17-repair-protocol) 🟠
18. [Snapshot System](#18-snapshot-system) 🔴
19. [Accounts Database (Funk)](#19-accounts-database-funk) 🔴
20. [Vinyl KV Store](#20-vinyl-kv-store) 🔴
21. [IPC / Tango Messaging](#21-ipc--tango-messaging) 🟠
22. [Process Sandboxing](#22-process-sandboxing) 🔴
23. [Cryptography (Ballet)](#23-cryptography-ballet) 🔴
24. [RPC / HTTP Server](#24-rpc--http-server) 🟠
25. [Forest (Fork Tree)](#25-forest-fork-tree) 🔴

---

## 0. Deep Dives

🔴 **HIGH**

- [x] Deep dive on sBPF VM divergences from Agave's rbpf - opcode semantics, JIT edge cases, memory mapping
  - [x] Reviewed all opcode implementations in `fd_vm_interp_core.c` including V0/V1/V2+ variants
  - [x] SUB_IMM operand swap (V2), MUL_IMM sign extension (V0), MOV_REG sign vs zero extension - all match Agave spec
  - [x] Division-by-zero: caught at validation time (`FD_VM_ERR_SIGFPE`), no runtime check - matches Agave's two-phase approach
  - [x] CALL_IMM entrypoint (imm==0x71e3cf81): stack pushed before validation, minor state divergence on fault vs Agave
  - [x] CALL_REG: no calldests check - matches Agave design (indirect calls can target any offset)
  - [x] Stack frame gap check (`!!(vaddr & 0x1000)`) only validates start address, not full range of multi-byte accesses - potential cross-frame read at page boundary (needs rbpf comparison)
  - [x] haddr==0 sentinel ambiguity for V3 rodata at vaddr 0 - production-unlikely (rodata never at host addr 0), fuzzing-relevant
  - [x] Input region binary search safe with guard in `fd_vm_find_input_mem_region` (cnt==0 check at line 401)
- [x] Hypothesis-driven attack stories:
  - [x] Can a malicious validator crash other validators via crafted shreds/repairs?
    - [x] FEC resolver: thorough pre-signature validation at fd_fec_resolver.c:498-600 (idx, fec_set_idx, data_cnt, tree_depth all bounds-checked)
    - [x] Shred tile: FD_LOG_CRIT at fd_shred_tile.c:1050 (store full) requires malicious slot leader producing valid signed FECs - not reachable by arbitrary remote peer
    - [x] Reed-Solomon recovered shreds are re-parsed and rejected if invalid (fd_fec_resolver.c:868)
    - [x] Repair tile: ping handling has multi-layer validation (known peer, rate limit, Ed25519 signature)
    - [x] No crash vectors found reachable from a non-leader remote attacker
  - [x] Can tile-to-tile IPC messages be spoofed or corrupted from external input?
    - [x] Tango IPC relies on OS-level memory protection (mmap), not cryptographic MACs - sound model
    - [x] Each receiver validates chunk ranges against [chunk0, wmark] - prevents cross-dcache reads
    - [x] `fd_tpu_reasm` bounds-checks `pub_slots` against `slot_cnt` with reset on OOB
    - [x] Gossip vote `transaction_len` truncated to ushort but memcpy uses full ulong (bounded by 1232-byte gossip MTU, low risk)
    - [x] QUIC tile `hdr_sz` derived from attacker-controlled IP IHL field via sig metadata (bounded by XDP validation)
  - [x] Are there QUIC/XDP parsing divergences that bypass network-layer validation?
    - [x] **FINDING NET-001**: IP fragmentation not checked in XDP BPF or userspace - fragments bypass port filter and deliver raw bytes to downstream tiles
    - [x] Missing `net_tot_len >= IHL` check in QUIC IP parser (fd_quic.c:2409) - allows parsing with inconsistent header lengths
    - [x] `RESET_STREAM` handler unimplemented (fd_quic.c:4949-4957) - stream slot leak DoS (likely covered by #9165 "unreleased TPU slots")
    - [x] Connection-level `rx_max_data` not enforced (fd_quic.c:5048-5063) - set to (1<<62)-1, no practical impact
    - [x] QUIC path re-parses IP/UDP independently (correct), while UDP path trusts `sig` hdr_sz from XDP tile
  - [x] Can snapshot loading be poisoned to corrupt accounts DB state?
    - [x] `BankIncrementalSnapshotPersistence` fields (full_slot, full_hash, etc.) silently discarded (ssmanifest_parser.c:1067-1071) - incremental snapshot base never validated against loaded full snapshot
    - [x] lthash check (blake3(lthash) vs advertised_hash) provides integrity but advertised_hash comes from same peer - no independent trust anchor
    - [x] `lthash_disabled` config flag bypasses all integrity checks
    - [x] Same-slot duplicate pubkey triggers `FD_TEST(0)` abort in `fd_snapin_tile_funk.c:240` - DoS via crafted snapshot
    - [x] Blockhash queue `hash_index` not bounds-checked (fd_ssload.c:48) - OOB write if gapped indices in snapshot
  - [x] Can the consensus/fork-choice (ghost/tower) be manipulated by timing attacks?
    - [x] **FINDING CONS-001**: Missing authorized voter check in `count_vote_txn` (tower_tile.c:745) allows TPU vote poisoning
    - [x] **FINDING CONS-002**: `is_purged` (tower.c:459) dereferences `fd_tower_blocks_query` result without NULL check
    - [x] `switch_check` temporarily removes ghost blocks from map during BFS (tower.c:477-507) - transient inconsistency
    - [x] `lockout_interval_key` truncates slots above 2^32 (tower.c:78-81) - future-dated collision
    - [x] Gossip vote forward confirmation assertion (tower_tile.c:535) may fire if ghost_blk pruned between replay and vote arrival
    - [x] `fd_ghost_count_vote` strict monotonicity check (ghost.c:418-421) - out-of-order vote processing acknowledged in comment
  - [ ] Manual review of recent feature-gate-gated code for consensus divergence risk
    - [ ] `fd_bpf_loader_serialization.c` `write_account()` lines 233-248: Mode 2 vs Mode 3 alignment padding arithmetic - `fd_ulong_sat_sub(FD_BPF_ALIGN_OF_U128, align_offset)` determines region vaddr offsets; mismatch with Agave causes memory translation errors
    - [ ] `fd_rewards.c` vs `fd_stakes.c` commission cascade: two structurally different code paths compute delayed commission (t-3 > t-2 > t-1 fallback); rewards path picks t-2 then overrides with t-3 from separate bank state source, stakes path uses direct ternary chain
    - [ ] `syscall_parameter_address_restrictions` completeness: verify the 6 sysvar syscalls with `vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START` checks match Agave's restricted set exactly
    - [ ] `fd_vm_interp_jump_table.c` `OVERRIDE_WITH_FALLBACK` macro for PQR (V2) vs JMP32 (V3) opcode mutual exclusivity - incorrect mapping is a consensus divergence on V3 programs
    - [ ] See SR/Feature_Gate_Review.md for full analysis

## 0B. Fuzzing-Guided Targeted Review

🔴 **HIGH** - Cross-cutting review targets derived from fuzzing campaign coverage gaps,
crash recovery patterns, and mutator blind spots. See `SR/Fuzzing.md` for campaign details.

**Key insight:** The fuzzers prove the happy path is correct across ~300M+ executions.
Bugs are in state-dependent edge cases, composition boundaries, and version/feature
interactions that require specific multi-step setups the fuzzer can't construct.

### 0B.1 FD_LOG_ERR/CRIT as Remote DoS Surface

FD uses FD_LOG_ERR (process abort) as an assertion mechanism throughout the execution layer.
Every FD_LOG_CRIT reachable from a crafted transaction is a validator crash. The fuzzer
tolerates these via siglongjmp but does not flag them as findings. If an attacker can craft
account data with an invalid discriminant and get a built-in program to read it, the
validator aborts. Key question: can invalid data enter an account via a prior transaction?

**Files:** `fd_vote_program.c`, `fd_vote_state_versioned.c`, `fd_system_program_nonce.c`,
`fd_executor.c`, `fd_bpf_loader_program.c`

- [x] Vote program discriminant crashes: FD_LOG_CRIT at lines 81, 99, 123, 143.
  NOT REACHABLE. `target_version` is derived from feature gate at line 1615
  (always V3 or V4), never from attacker input. Default branches are defensive.
- [x] Vote instruction dispatch: FD_LOG_CRIT at lines 1881, 1948, 2287.
  NOT REACHABLE. Instruction discriminant validated by `fd_vote_instruction_deserialize`
  (fd_vote_codec.c:1175 returns error for unknown discriminants). Lines 2239, 2260,
  2283 gated by hardcoded-zero feature flags (lines 1629-1631), always return
  INVALID_INSTR_DATA before reaching FD_LOG_CRIT.
- [x] Vote state serialization crashes: ~20 FD_LOG_CRIT in `fd_vote_state_versioned.c`.
  NOT REACHABLE. All triggered by unsupported `self->kind` value. Vote program only
  deserializes into V3 or V4 (target_version from feature gate). Owner-change-requires-
  empty-data invariant prevents account data corruption. Line 229 (serialize failure)
  guarded by size check at line 223. Line 686 (try_convert_to_v4 default) unreachable
  because target_version always V3 or V4.
- [x] Vote invariant: FD_LOG_CRIT at line 702 "landed votes is empty". NOT REACHABLE.
  Function entry asserts `!deq_fd_landed_vote_t_empty(new_state)` at line 497. No code
  path between entry and line 701 empties the deque (only `votes` is modified at 713,
  not `new_state`). Defensive check only.
- [x] Nonce state discriminant crashes: FD_LOG_CRIT at lines 164, 336, 536, 713, 765.
  NOT REACHABLE. Nonce accounts are owned by system program; only system program can
  modify their data. System program always writes valid discriminants (0 or 1).
  Owner-change-requires-empty-data invariant (fd_borrowed_account.c:42,
  fd_borrowed_account_is_zeroed) prevents Assign-corrupt-Assign-back attack.
  All discriminant assignments in fd_system_program_nonce.c use valid enum values.
- [x] Nonce blockhash queue: FD_LOG_CRIT at line 889. NOT REACHABLE from attacker.
  Only fires at genesis/slot 0 before any blockhash is registered. Validator-internal
  startup condition, not triggerable by transaction data.
- [x] Executor FD_LOG_CRIT at line 178/183: NOT REACHABLE. Rent state discriminant
  is computed locally from lamports/dlen (fd_executor.c:204-220), never read from
  untrusted account data. Only produces values 0, 1, 2.
- [x] Executor FD_LOG_CRIT at line 807: NOT REACHABLE under normal operation. Fee payer
  existence verified during transaction validation (line 833-837) before this point.
  Would require account deletion between validation and fee deduction (invariant violation).
- [x] Executor FD_LOG_CRIT at line 1569: "leaked account references". LOW RISK.
  Fires if `ro_active + rw_active` changes across fd_execute_instr. This requires an
  internal bug in borrow tracking, not attacker input. BPF programs can't directly
  manipulate borrow counts - borrows are managed by the runtime via
  fd_guarded_borrowed_account_t. CPI cleanup in fd_instr_stack_pop releases borrows.
  Would only trigger from a runtime bug (leaked fd_borrowed_account_drop call).
- [x] BPF loader FD_LOG_CRIT at line 388: NOT REACHABLE. Stack-allocated buffer of
  FD_SBPF_SYSCALLS_FOOTPRINT bytes. fd_sbpf_syscalls_new/join on pre-allocated fixed-
  size buffer cannot fail under normal conditions. Defensive only.
- [x] Authorized voters: FD_LOG_CRIT at `fd_authorized_voters.c:94`. NOT REACHABLE.
  Pool capacity=6, max theoretical voters=4 (1 current + 3 future epochs).
  fd_authorized_voters_purge_authorized_voters removes expired entries on each access.
  Authorize instructions can only add 1 voter per call. Pool exhaustion impossible.

### 0B.2 Post-Validation Execution Logic

80% of fuzzer inputs fail protobuf decode. Of the remaining 20%, many fail harness
preconditions. The code paths AFTER all validation gates are proportionally under-tested.
These paths handle the actual state mutation and are where conformance divergences live.

**Files:** `fd_vote_program.c`, `fd_system_program.c`, `fd_bpf_loader_program.c`,
`fd_system_program_nonce.c`

- [x] Vote lockout state modification: reviewed `process_new_vote_state` (line 483+)
  and `fd_vsv_process_next_vote_slot` (line 515+). Lockout doubling via
  `pow(INITIAL_LOCKOUT, confirmation_count)` at line 631-632. Confirmation count
  clamped to MAX_LOCKOUT_HISTORY=31 (line 630) - protective divergence from Agave
  (FD clamps, Agave doesn't) but both saturate in practice. Off-by-one analysis:
  line 547 (`>`) checks proposed state ordering, line 634 (`>=`) checks conflict -
  different semantics, both correct per Agave references. Tower at max: pop_expired_votes
  called BEFORE size check (line 522 before 532) - correct per Agave, oldest becomes
  root. No inconsistency from simultaneous expiration - tail pops are idempotent.
- [x] Vote `pop_expired_votes` (fd_vote_state_versioned.c:501-512): removes votes
  where `last_locked_out_slot < next_vote_slot`. Consistent with lockout_conflict check
  at line 634 (`>=`). No inconsistency found.
- [x] Stake withdrawal: N/A for native code review. Stake program is NOT a native
  builtin in Firedancer - it's delegated to BPF (Core BPF migration via
  `migrate_stake_program_to_core_bpf` feature). fd_builtin_programs.c:77-87 lists
  builtins: system, vote, BPF loaders, compute budget, ZK programs - no stake.
  Custodian checks, rent-exempt validation, and withdrawal logic are in BPF bytecode.
- [x] BPF loader `deploy_with_max_data_len` authority: lines 1153-1157. The check
  `(authority_key==NULL) != (!has_authority_address)` correctly handles all 4 cases:
  NULL key + no authority = pass (immutable), NULL key + has authority = error,
  non-NULL key + no authority = error, non-NULL key + has authority = compare keys.
  Signer check at line 1158 verifies authority signed. No bypass possible.
- [x] BPF loader `close_program`: line 1893-1897 prevents recipient == account being
  closed. Authority (account[2]) being the same as the account (account[0]) is fine -
  authority is validated as signer before the close modifies state. The authority's
  signature was verified at transaction level. Not exploitable.
- [ ] System program `CreateAccountWithSeed` / `AllocateWithSeed`: seed-derived address
  validation. Is the seed length bounded? Can a very long seed cause excessive hashing?
- [x] Nonce advance: single-threaded execution within the executor (fd_execute_instr is
  single-threaded per slot). No TOCTOU risk - state reads and writes are atomic within
  a single instruction execution. The blockhash update is: read old state -> validate ->
  write new state, all within the same function call with no yield points.

### 0B.3 Feature Gate Interactions

Feature gate changes execution semantics. The fuzzer pre-populates all 215 mainnet features
but doesn't explore feature *combinations*. The interesting bugs are where enabling feature A
changes behavior of code path B in an unanticipated way.

**Files:** `fd_features_generated.c`, `fd_vm_interp_core.c`, `fd_bpf_loader_program.c`,
`fd_executor.c`, `fd_vote_program.c`

- [ ] Feature interaction: `enable_sbpf_v2` + `syscall_parameter_address_restrictions`.
  V2 changes call semantics AND restricts syscall address parameters. If one is enabled
  without the other, do the VM's memory checks remain consistent?
- [x] Feature interaction: `direct_mapping` + CPI. Direct mapping does NOT create a
  validation gap. The realloc bounds check at fd_vm_syscall_cpi_common.c:559 runs
  BEFORE fd_vm_cpi_update_caller_account_region (cpi.c:317). The region_sz update
  at line 317 only fires after the bounds check passes. When restrictions are on
  (mainnet), data_vaddr validated against acc_region_meta (line 381), data_len bounded
  by original_data_len + MAX_PERMITTED_DATA_INCREASE (line 433). Call order verified:
  UPDATE_CALLER_ACC (line 931, includes bounds check) -> update_caller_account_region
  (line 950, updates region). Read-only enforcement via region->is_writable flag
  checked at fd_vm_private.h:429.
- [x] Vote program version upgrade: `fd_vsv_try_convert_to_v4()` (fd_vote_state_versioned.c:591).
  SAFE. Conversion is in-memory only; account data not written until
  `fd_vsv_set_vote_account_state` at fd_vote_program.c:1318. If CU exhaustion occurs
  between conversion and serialization, the transaction rolls back entirely (no partial
  account state). V3/V4 deserialization adapts to the version found in account data.
  Commission conversion uses `fd_ushort_sat_mul(commission, 100)` - saturating, no overflow.
- [x] `OVERRIDE_WITH_FALLBACK` macro: SAFE. 16 overlapping opcodes (not 12 as commented)
  between PQR (V2) and JMP32 (V3). Each sBPF version has its own complete 256-entry jump
  table built at compile time (fd_vm_interp_jump_table.c:202-208). Static assertions at
  fd_vm_private.h:196-200 verify PQR and JMP32 are mutually exclusive for each version.
  `interp_jump_table[sbpf_version][opcode]` dispatch is correct. Programs carry their
  version in ELF metadata; deployment validates against min/max allowed versions.
- [x] Fee rate governor: fd_runtime.c:395 `max = target * 10`. Unchecked u64 multiplication.
  Target comes from genesis config (fd_runtime.c:1573), fixed at network genesis, not
  modifiable by attacker transactions. On mainnet, target=10000, so max=100000. Would
  only overflow if target > 2^64/10 (~1.8e18), which is impossible on mainnet genesis.
  Matches Agave's FeeRateGovernor::new_derived. Not exploitable.
- [x] Rent calculation: fd_sysvar_rent1.c:8-13 uses `(double)((data_len + 128) * lamports_per_uint8_year) * exemption_threshold`. This is identical to Agave's rent.rs formula.
  `fd_rust_cast_double_to_ulong` (fd_cast.h:20-46) handles edge cases (NaN -> 0,
  infinity -> ULONG_MAX, negative -> 0) matching Rust saturating cast semantics.
  SIMD-0194 deprecation (fd_runtime.c:544-563) pre-multiplies rate by threshold,
  setting threshold to 1.0 for all future calculations. Conformance assured.

### 0B.4 CPI Privilege Escalation and Composition Bugs

CPI is the single largest confirmed gap in fuzz coverage (~1,557 lines never differentially
tested). This is where independently-correct programs interact and where the most complex
validation logic resides.

**Files:** `fd_vm_syscall_cpi.c`, `fd_vm_syscall_cpi_common.c`, `fd_vm_syscall_pda.c`

- [x] Privilege escalation - writable: `fd_vm_syscall_cpi.c:151` checks correctly.
  The OR-combination during deduplication (lines 122-123) merges privileges, then
  line 151 checks merged privileges against CALLER's permissions. Providing the same
  account twice (once writable, once not) merges to writable, but the check still
  verifies the caller has writable permission. Matches Agave. Not exploitable.
- [x] Privilege escalation - signer: line 159 checks correctly. Merged signer flag
  verified against caller's signer status OR PDA derivation via
  `fd_vm_syscall_cpi_is_signer()`. Duplicate entries in seeds list don't bypass - the
  search finds the first match and returns. Empty seeds list = no PDA signers found.
- [x] De-duplication: O(n^2) at lines 100-106 bounded by
  FD_VM_CPI_MAX_INSTRUCTION_ACCOUNTS=255. Max 65K ushort comparisons - negligible
  compared to CPI invoke cost (CU charged at line 262-265). Not a DoS vector.
- [ ] Account metadata flags: TODO at `fd_vm_syscall_cpi_common.c:86`. NEEDS ANALYSIS -
  need to identify what specific flags are referenced.
- [x] CU accounting: FIXME at line 280 is about whether base cost is included in CU
  charge for executable accounts during CPI. This is a conformance concern (CU metering
  difference), not a privilege escalation. The comment says "changes CU behaviour from
  main" - potential minor divergence from Agave but not exploitable.
- [x] Double borrow: FIXME at lines 285-287. The `fd_borrowed_account_drop` at line 287
  releases the callee account borrow so a subsequent borrow in the inner loop doesn't
  fail. This is a code hygiene issue (ideally borrows would be scoped), not an exploit
  vector - the drop happens before any modification, so no stale-data or mutable-alias
  risk.
- [x] PDA signer validation: fd_vm_syscall_pda.c. Seed limits correctly enforced:
  max 16 seeds (FD_VM_PDA_SEEDS_MAX, checked at lines 35-38, 44-46, 119-127),
  max 32 bytes per seed (FD_VM_PDA_SEED_MEM_MAX, checked at lines 52-55).
  Off-curve check at line 87-91 uses full Ed25519 point decompression via
  fd_ed25519_point_validate -> fd_ed25519_point_frombytes (fd_curve25519.c:35-66).
  Rejects on-curve PDAs with FD_VM_SYSCALL_ERR_INVALID_PDA. Protocol-correct.
  PDA collision with existing accounts is prevented by off-curve requirement -
  all real Ed25519 pubkeys are on-curve, PDAs are guaranteed off-curve.
- [x] Memory region overlap in CPI: `fd_vm_syscall_cpi_common.c:329-473`. When
  `syscall_parameter_address_restrictions` is on (mainnet), data_vaddr validated
  against `acc_region_meta->vm_data_addr` (line 381) and data_len bounded by
  `original_data_len + MAX_PERMITTED_DATA_INCREASE` (line 431-433). These regions
  are assigned by the BPF loader serialization, which lays them out sequentially.
  When restrictions are off (legacy), data_haddr is translated via FD_VM_MEM_HADDR_ST
  which validates against valid VM regions. No overlap possible through the validated
  paths. The `virtual_address_space_adjustments` path (line 457-462) uses
  `fd_ulong_sat_sub` which clamps underflow to 0 - safe but could point to wrong
  region base if vaddr is forged. However, this is still within the input region
  mapping and bounded by translated data_len.

### 0B.5 VM Call Frame Machinery

The VM interpreter found 0 mismatches in 265M executions, but CALL_IMM with valid calldests
was never tested (calldests=NULL in harness). The call/return stack frame machinery is
complex and has distinct behavior across sBPF versions.

**Files:** `fd_vm_interp_core.c`, `fd_vm.h`, `fd_vm.c`

- [x] Stack frame depth limit: FD_VM_STACK_FRAME_MAX=64 (fd_vm_base.h:144). Enforced
  at fd_vm_interp_core.c:293 (`if(++frame_cnt>=frame_max) goto sigstack`). Error code
  FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED matches Agave.
- [ ] Register save/restore across call frames: NEEDS ANALYSIS. Stack frame and register
  save area are in the same memory region - potential for overwrite via memory store.
- [ ] Return from function EXIT register restore: NEEDS ANALYSIS for cross-version.
- [x] CALL_REG targeting LDDW: fd_vm_interp_core.c:800-820. NO check prevents targeting
  second word of LDDW. FIXME at fd_vm.c:398 acknowledges this. Static jump targets ARE
  checked (line 380 rejects JMP to ADDL_IMM), but CALL_REG is not. This is a known
  design choice that matches Agave (both lack the check for indirect calls).
- [x] R10 mutation: fd_vm.c:450-459 validates destination register. R10 is read-only
  EXCEPT for: (1) store operations (r10 as base address for STX), (2) ADD64_IMM with
  aligned amounts when dynamic stack frames are enabled (SIMD-0166, V2+). Both exceptions
  are intentional and match Agave. FIXME at line 284 is about code quality, not a bug.

### 0B.6 Epoch Boundary Arithmetic

Stake rewards, delegation warmup/cooldown, and vote lockout all depend on epoch
arithmetic. The fuzzer generates random values; it doesn't generate the specific
boundary conditions where epoch transitions cause state changes.

**Files:** `fd_stake_rewards.c`, `fd_stake_delegations.c`, `fd_rewards.c`, `fd_stakes.c`

- [x] Epoch truncation: CONFIRMED. fd_stake_delegations.h:96-97 stores activation_epoch
  and deactivation_epoch as `ushort`. Truncation at fd_stake_delegations.c:262-263 uses
  `(ushort)fd_ulong_min(epoch, USHORT_MAX)`. Values > 65535 are clamped to 65535 (not
  wrapped). At ~2 epochs/day, this overflows in ~89 years. fd_stakes.c uses these in
  comparisons with `target_epoch` (ulong). Low immediate risk but potential long-term
  conformance divergence if Agave stores full 64-bit epochs. NOT exploitable today.
- [ ] Commission cascade divergence: `fd_rewards.c` vs `fd_stakes.c` compute commission
  differently (t-3/t-2/t-1 fallback). Are both paths guaranteed to produce the same
  result? What if the commission changed at t-2 but the reward calculation uses t-3?
- [ ] Rent collection at epoch boundary: does rent collection happen before or after
  stake reward distribution? If the order differs from Agave, accounts may have different
  balances during reward calculation, producing different rewards.
- [ ] Zero-stake delegation: what happens when a stake account is delegated with 0 lamports?
  Does the warmup calculation handle zero stake correctly (no division by zero)?
- [ ] Effective stake during deactivation cooldown: the effective stake decreases each
  epoch. At what point does it reach zero? Is there an off-by-one where FD reports 0
  but Agave reports 1 (or vice versa)?

### 0B.7 Unchecked Integer Arithmetic in Fee/Lamport Paths

**Files:** `fd_system_program.c`, `fd_executor.c`, `fd_runtime.c`

- [ ] System program transfer: `fd_system_program.c:92-117`. Lamport addition to
  recipient uses `checked_add()` - verify error code matches Agave for overflow.
- [ ] System program create_account: lamport deduction + space allocation. Can the space
  parameter be u64 max, causing overflow in rent-exempt calculation?
- [x] Fee deduction in executor: fd_executor.c:821 FD_LOG_ERR. NOT reachable - fee payer
  validated at line 833-837 before this point. Rent collection and fee deduction happen
  within the same atomic slot execution.
- [x] Fee rate governor overflow: see 0B.3 section - confirmed not exploitable (genesis value).
- [x] Compute budget cap: FD_MAX_COMPUTE_UNIT_LIMIT=1,400,000 (fd_compute_budget_program.h:10).
  Matches Agave exactly. u32 max silently capped via fd_ulong_min at line 91. No error,
  consistent with Agave behavior.

### 0B.8 Account Data Serialization Boundaries

BPF programs receive serialized account data. The serialization format has alignment
requirements that differ between modes. A mismatch here means programs see different
data on FD vs Agave.

**Files:** `fd_bpf_loader_serialization.c`, `fd_vm_syscall_cpi_common.c`

- [x] Mode 2 vs Mode 3 alignment: fd_bpf_loader_serialization.c:231-248.
  FD_BPF_ALIGN_OF_U128=8 (fd_runtime_const.h:145). Mode 2 (no direct mapping): pads
  by `align_offset = align_up(dlen, 8) - dlen`. Mode 3 (direct mapping): pads by 8,
  advances metadata pointer by `sat_sub(8, align_offset)`. When dlen is exact multiple
  of 8: align_offset=0, Mode 3 advances by 8 (full padding). Matches Agave's
  serialization.rs#L171-L187 per reference in code comments.
- [ ] Account data realloc during CPI: NEEDS ANALYSIS for zero-padding on shrink.
- [x] `MAX_PERMITTED_DATA_INCREASE`: fd_runtime_const.h:144 defines as 10240UL (10 KiB).
  Matches Agave exactly. Used in BPF serialization, CPI realloc bounds, and memory
  layout calculations.
- [ ] Serialization of duplicate accounts: NEEDS ANALYSIS.

## 0C. Advanced Attack Vectors (Round 2)

🔴 **HIGH** - Novel attack vectors identified after completing the first-pass review.
Focus: subtle logic bugs, rounding/ordering divergences, and DoS vectors that require
multi-step or timing-dependent exploitation.

### 0C.1 PoH Tick Boundary Crash (Leader DoS)

A FD_LOG_CRIT at fd_poh.c:679 fires when a microblock mixin arrives at the exact tick
boundary (`hashcnt % hashcnt_per_tick == hashcnt_per_tick - 1`). This kills the leader
validator. If an attacker can influence pack timing (via transaction ordering, QUIC flow
control, or compute-heavy transactions that stall execle), this is a remotely-triggerable
leader crash.

**Files:** `src/discof/poh/fd_poh.c`, `src/discof/poh/fd_poh_tile.c`

- [x] Traced pack -> execle -> poh path. NOT REACHABLE in production. The hashing
  loop at fd_poh.c:557 explicitly prevents hashcnt from landing at hashcnt_per_tick-1:
  `target_hashcnt -= (!low_power_mode) & (target_hashcnt%hpt == hpt-1)`.
  This means poh->hashcnt can NEVER be at the tick boundary pre-mixin value in
  production (low_power_mode = hashcnt_per_tick==1, development only, line 378).
  The FD_LOG_CRIT at line 679 is a defensive assertion that is unreachable when
  hashcnt_per_tick > 1 (always true on mainnet: 12500 or 62500).
- [x] low_power_mode is hashcnt_per_tick==1 (fd_poh.c:378). Only for dev/test.
  Not a valid attack vector on production validators.

### 0C.2 Execle CU Cost Tracking Overflow

fd_execle_tile.c:290 casts `compute_unit_limit - compute_meter` from u64 to uint (u32).
If the subtraction wraps (e.g., compute_meter > compute_unit_limit due to a bug), the
cast produces a small u32 value. The subsequent check at line ~295 compares against
requested CUs - if the actual CU appears smaller than requested due to truncation, the
cost tracking underreports, and pack re-credits too much CU budget.

**Files:** `src/discof/execle/fd_execle_tile.c`

- [x] compute_unit_limit and compute_meter: both ulong (fd_compute_budget_details.h:17,19).
  compute_unit_limit capped at 1,400,000 (fd_compute_budget_program.c:91).
  compute_meter starts at compute_unit_limit and only decreases. Subtraction
  `limit - meter` always in [0, 1.4M], fits in u32 (max 4.3B). Cast is safe.
  No code path increases compute_meter. NOT exploitable.

### 0C.3 Forest Orphan Pool Exhaustion (Validator DoS)

The forest tile maintains orphan blocks (blocks whose parents haven't arrived yet).
The reconnaissance found no eviction policy for orphans (TODO at fd_forest.c:751).
An attacker sending shreds for slots with non-existent parents can fill the orphan pool.

**Files:** `src/discof/forest/fd_forest.c`

- [x] Forest pool: 4096 slots (tiles.repair.slot_max in default.toml:1497). Shared
  across ancestry, frontier, orphaned, and subtrees maps. No separate orphan limit.
- [x] Eviction: priority-based (highest unconfirmed orphan leaf first, fd_forest.c:749-876).
  TODO at line 751 notes incomplete eviction policy. Eviction can fail if all blocks
  are confirmed/rooted (line 885-886 returns NULL).
- [x] Shred validation: ALL shreds (turbine + repair) pass through fd_fec_resolver
  with leader signature verification (fd_shred_tile.c:926-948). Leader schedule
  checked at line 929. Attacker can only create shreds for slots they lead.
- [x] NOT exploitable by non-leader attacker. A malicious leader can create orphans
  during their own slots only (handful per epoch), far from 4096 needed to exhaust
  pool. Additionally, orphans for old slots (parent < root) are rejected at
  fd_repair_tile.c:757. The pool eviction heuristic (evict highest unconfirmed
  orphan leaf first) would preferentially evict attacker's orphans.
- [x] No age-based expiration exists, but eviction + leader-signature requirement
  makes pool exhaustion impractical without majority stake.

### 0C.4 Fee/Reward Rounding Divergence from Agave

STAKES-001 proved that 1 lamport difference in rewards causes bank hash divergence.
Multiple fee/reward calculations use integer division with truncation. If the rounding
direction or order of operations differs from Agave, bank hashes diverge.

**Files:** `src/flamenco/runtime/fd_runtime.c`, `src/flamenco/rewards/fd_rewards.c`

- [ ] Fee burn: fd_runtime.c:307 `fee_burn = execution_fees / 2`. Does Agave use
  identical truncating division? What if execution_fees is odd?
- [ ] Tips commission: fd_runtime.c:367 `tips * 6 / 100`. Is the 6% commission rate
  correct? Does Agave use the same formula or a different percentage/calculation?
- [ ] Inflation rewards float-to-int: fd_rewards.c:308 casts `(double)(...) * rate`
  to ulong. IEEE 754 double → u64 truncation must match Agave's Rust `as u64`.
  Rust truncates toward zero; C truncates toward zero. But intermediate rounding of
  the double arithmetic could differ between C and Rust compilers.
- [ ] Commission split: fd_rewards.c:211-214 uses u128 intermediate.
  `(uint128)on * (uint128)commission / (uint128)100` - does Agave use the same
  order of multiplication then division, or division first?
- [ ] Fee payer rent check AFTER fee deduction: fd_executor.c:260-266. If fee makes
  account non-rent-exempt, is it rejected same as Agave? Different error code?

### 0C.5 Sysvar Update Ordering at Slot/Epoch Boundary

fd_runtime.c:349-371 (fd_runtime_freeze) updates sysvars in a specific order. If this
order differs from Agave's bank::freeze(), the resulting account states differ.

**Files:** `src/flamenco/runtime/fd_runtime.c`

- [x] Order comparison: FD freeze (fd_runtime.c:350-371) = recent_hashes -> slot_history
  -> fees -> tips -> incinerator. Agave freeze (bank.rs:2717-2719) = fees -> slot_history
  -> incinerator. Different ORDER but operations modify independent accounts (no
  cross-dependencies). Sysvar updates do not read each other's output.
- [x] Pre-transaction sysvar order: FD = Clock, SlotHashes, LastRestartSlot
  (fd_runtime.c:746-752). Agave = SlotHashes, StakeHistory, Clock, LastRestartSlot
  (bank.rs:1458-1461). Clock and SlotHashes are independent. StakeHistory only runs
  at epoch boundaries (Agave bank.rs: `if epoch == self.epoch() return`), handled
  separately in FD's epoch transition code (fd_bank.c).
- [x] Capitalization: updated atomically via fd_accdb_svm_close_rw (fd_accdb_svm.c:63-81)
  which adjusts cap in same function that commits account state. No window of
  inconsistency.
- [ ] Epoch boundary: rent collection vs rewards ordering - NEEDS ANALYSIS with Agave
  comparison at epoch boundary specifically.

### 0C.6 Zero-Lamport Account Lthash Divergence

fd_hashes.c:34-36 excludes zero-lamport accounts from lthash. The exact criteria for
exclusion must match Agave. Edge cases: account created and deleted in same slot,
account with 0 lamports but non-empty data, incinerator account.

**Files:** `src/flamenco/runtime/fd_hashes.c`, `src/flamenco/runtime/fd_accdb_svm.c`

- [ ] When an account's lamports reach 0, is it removed from lthash immediately or
  at slot boundary?
- [ ] What about the incinerator account (special case)?
- [ ] If a program sets an account's lamports to 0 but doesn't delete it (data remains),
  is it included in lthash?
- [ ] Compare fd_hashes.c blake3 serialization format byte-for-byte with Agave's
  accounts_hash.rs

### 0C.7 Sign Tile Starvation (Block Production DoS)

Multiple tiles compete for the sign tile: shred (signing produced shreds), gossip
(signing gossip messages), repair (signing repair requests), txsend (signing vote txns).
If one channel is flooded, others may starve.

**Files:** `src/discof/sign/fd_sign_tile.c`, topology link definitions

- [ ] What is the sign tile's throughput (sigs/sec)?
- [ ] How are requests prioritized between tiles?
- [ ] Can a repair storm (triggered by orphan blocks, see 0C.3) flood the sign tile
  and prevent shred signing, stalling block production?
- [ ] Is there backpressure or flow control on sign requests?

### 0C.8 Uninitialized Memory in Account Hash / Bank Hash Path

If any field used in the bank hash computation contains uninitialized memory, the hash
is non-deterministic across runs. This would cause chain splits between FD validators
(not just FD-vs-Agave divergence).

**Files:** `src/flamenco/runtime/fd_hashes.c`, `src/funk/fd_funk_rec.c`

- [ ] Check fd_hashes.c account hash: is every field in the blake3 input fully
  initialized? (lamports, data, executable flag, rent_epoch, owner, pubkey)
- [ ] Are there any struct padding bytes that could leak into the hash?
- [ ] Check funk record allocation: when a new record is created, is it zero-initialized?
- [ ] Check account metadata: is rent_epoch always set, or can it be uninitialized
  for newly created accounts?

### 0C.9 Replay Fork Selection Crash on Pruned Parent

fd_replay_tile.c:770-790 calls FD_LOG_CRIT when a block's parent merkle root is not
found in block_id_map. If forest prunes a block that replay still references (race
between root advancement and block processing), the validator crashes.

**Files:** `src/discof/replay/fd_replay_tile.c`, `src/discof/forest/fd_forest.c`

- [ ] Can an attacker influence root advancement timing (via vote poisoning, see CONS-001)
  to create a window where replay references a pruned parent?
- [ ] Is block_id_map populated from forest or independently? Can they get out of sync?
- [ ] What happens if an equivocating leader produces a block referencing a very old parent?

### 0C.10 Funk Transaction State Machine Race (Multi-Execle DoS)

fd_funk_txn.c:30-40 crashes (FD_LOG_CRIT) on state machine race detection. In multi-execle
configurations, concurrent access to funk transactions is expected. If the state machine
transitions aren't fully atomic, concurrent execle tiles can trigger the crash.

**Files:** `src/funk/fd_funk_txn.c`

- [ ] How many execle tiles are configured by default?
- [ ] What operations can run concurrently? (read-read OK, read-write race?)
- [ ] Is the state transition using CAS (compare-and-swap), and if so, what's the
  retry/fallback behavior?
- [ ] Can transaction execution trigger concurrent funk modifications from different
  execle tiles on the same account?

### 0C.11 Transaction Rollback and Nonce Semantics

Investigated whether transaction failure handling differs between FD and Agave.

- [x] Nonce advancement on failure: FD correctly advances nonce ONLY when authority
  check passes (fd_system_program_nonce.c:997-1064). Falls through to error at line 1069
  if no authorized signer found. DurableNonce semantics (advance even on later instruction
  failure) correctly implemented. Matches Agave.
- [x] Fee payer rent check: fd_executor.c:252 checks rent-exempt minimum for nonce fee
  payers but allows regular fee payers to transition from rent-exempt to rent-paying.
  fd_executor_check_rent_state at line 269 validates post-fee state. Matches Agave.
- [x] Precompile execution: happens during verification phase, not instruction execution.
  CU charging for precompiles handled in compute budget. TODO at fd_runtime.c:948
  notes timing difference but result is functionally equivalent.

### 0C.12 Inflation Rewards Float Precision

- [x] FD uses C `pow()` (fd_rewards.c:23). Agave uses Rust `f64::powf`. Both call
  system libm `pow()` on x86-64 Linux. Verified `pow` is external library call (not
  compiler intrinsic) via `nm` on libfd_flamenco.a. `-ffast-math` in build flags does
  NOT affect external pow() calls. `__FINITE_MATH_ONLY__` is set but inflation params
  are well-behaved constants (no NaN/Inf). Identical results guaranteed on same platform.
- [x] Float-to-ulong cast: `fd_rust_cast_double_to_ulong` matches Rust `as u64` semantics
  (truncation toward zero, with saturation for out-of-range values).

### 0C.13 InvalidWritableAccount Error Code

- [x] FD_RUNTIME_TXN_ERR_INVALID_WRITABLE_ACCOUNT (-20) is defined but never returned.
  Checked Agave: also never returned in production code (only in tests and serialization).
  This is a legacy error code in both implementations. Not a divergence.

## 1. QUIC / Network Layer

🔴 **HIGH**

**Files:** `src/waltz/quic/fd_quic.c`, `src/waltz/quic/fd_quic_conn.c`, `src/waltz/quic/fd_quic_conn_map.h`, `src/waltz/quic/fd_quic_retry.h`, `src/waltz/quic/crypto/`, `src/disco/net/xdp/fd_xdp_tile.c`

### 1.1 Retry Token Security

- [x] **QUIC-001**: Verify AES-GCM retry token IV is generated from a CSPRNG (not `fd_rng_t`)
  - [x] ✅ `retry_secret` and `retry_iv` generated from `fd_rng_secure()` (CSPRNG via `getrandom(2)`) at startup
  - [x] ✅ `token_id` uses `fd_rng_t` (non-crypto) but 96-bit nonce space makes birthday bound ~2^48, infeasible
  - [x] ✅ No counter wrap-around issue - 96-bit random nonce per token
  - **Note:** Developers aware of tradeoff (see comment at `fd_quic_retry.h:82-87`). PRNG seed is 32-bit (brute-forceable from observed traffic) but nonce prediction without key knowledge is useless since `retry_secret` is CSPRNG-generated

- [x] **QUIC-002**: Verify retry token IP/port binding cannot be bypassed
  - [x] ✅ Token validates source IP and UDP port; also checks ODCID size
  - [x] ✅ Retry mechanism requires completing stateless handshake (prevents spoofed IPs)
  - [x] ✅ Token expiry enforced via `FD_QUIC_DEFAULT_RETRY_TTL` (1s)

### 1.2 Connection State Machine

- [x] **QUIC-003**: Verify connection state transitions reject invalid orderings
  - [x] ✅ Stream frames only allowed in 0-RTT/1-RTT packets per `fd_quic_frame_type_allowed()` (line 937); 1-RTT requires TLS handshake completion
  - [x] ✅ `fd_quic_conn_free` sets state to INVALID with memory fences, removes from conn_map, then returns to free list
  - [x] ✅ Double-free checked with `FD_LOG_CRIT` at line 3996-3998

- [x] **QUIC-004**: Verify connection map hash function resists adversarial collisions
  - [x] ✅ `MAP_KEY_HASH(k,s) ((uint)k)` truncates to 32-bit, but keys (`our_conn_id`) are server-generated via `fd_rng_ulong()`, not attacker-controlled
  - [x] ✅ Full 64-bit key comparison at query time prevents cross-connection data leaks
  - [x] ✅ PRNG output sufficiently uniform in low 32 bits to avoid natural clustering

- [x] **QUIC-005**: Verify per-address connection limits exist
  - [x] ⚠️ No per-IP limiting mechanism exists; any IP can consume all connection slots
  - [x] ✅ QUIC retry (enabled by default) requires round-trip before connection allocation
  - [x] ✅ Covered by known issue #9165 ("low-bandwidth DoS") - excluded from contest scope

### 1.3 Packet Parsing

- [x] **QUIC-006**: Verify varint decoding correctness at boundary values
  - [x] ✅ `msb2 = buf[cur_byte] >> 6u` always produces 0-3; switch handles all cases + `default: FD_LOG_CRIT`
  - [x] ✅ Truncated varint: `cur_byte + vsz > sz` check before `FD_LOAD` (parsers.h:73)
  - [x] ✅ Max varint (2^62-1): sum of two varints < 2^63, fits in `ulong`

- [x] **QUIC-007**: Verify CRYPTO frame reassembly cannot cause OOB write
  - [x] ✅ Buffer bounded: `FD_QUIC_TLS_RX_DATA_SZ = 2048`; `rcv_hi > 2048` rejected (fd_quic.c:2843)
  - [x] ✅ `rx_sz = (ushort)rcv_hi` safe since rcv_hi <= 2048
  - [x] ✅ Overlapping writes require valid encrypted packets (TLS-protected)

- [x] **QUIC-008**: Verify ACK frame processing cannot cause integer overflow
  - [x] ✅ Underflow: `skip + length > cur_pkt_number` checked at line 4894
  - [x] ✅ ACK delay exponent: validated to max 20 during transport param parsing (fd_quic_transport_params.c:37)
  - [x] ✅ ACK count bounded by packet buffer size (each range >= 2 bytes, max ~750 per 1500-byte packet)

- [x] **QUIC-009**: Verify STREAM frame ID bounds checking
  - [x] ✅ Stream ID checked against `conn->srx->rx_sup_stream_id` at line 5051
  - [x] ✅ `data_sz > p_sz` checked at line 5042
  - [x] ✅ Flow control: `offset + data_sz` checked against `initial_rx_max_stream_data` (line 5059)

### 1.4 GRE / XDP Networking

- [x] **QUIC-010**: Verify GRE encapsulation source IP is not attacker-controlled
  - [x] ✅ GRE outer IPs loaded from kernel netlink (`IFLA_GRE_LOCAL`/`IFLA_GRE_REMOTE`), not user config
  - [x] ✅ Requires local privileged access to modify network interfaces - out of scope (remote-only attacker model)

- [x] **QUIC-011**: Verify XDP port filter handles edge cases
  - [x] ✅ Port 0 explicitly skipped: `fd_xdp1.c:198` `if(!port) continue;`
  - [x] ✅ VLAN tags not handled - VLAN-tagged packets pass to kernel (not redirected), availability impact only
  - [x] ⚠️ Hash-based load balancing (`fd_disco_base.h:78`) uses `fd_ulong_hash` with src IP/port - attacker can concentrate traffic on one net tile, but limited DoS impact

---

## 2. TLS 1.3 Implementation

🔴 **HIGH**

**Files:** `src/waltz/tls/fd_tls.c`, `src/waltz/tls/fd_tls_asn1.h`, `src/waltz/tls/fd_tls_estate.h`

- [x] **TLS-001**: Verify `FD_TEST` assertions replaced with runtime checks in production build
  - [x] ✅ `FD_TEST` expands to `FD_LOG_ERR` which is `__attribute__((noreturn))` - NEVER compiled out, even in release
  - [x] ✅ HKDF label bounds: all callers use hardcoded labels (max 12 bytes, e.g. "c hs traffic") - well within 64-byte `LABEL_BUFSZ`
  - [x] ✅ Not attacker-reachable: `label_sz` and `context_sz` are compile-time constants at every call site

- [x] **TLS-002**: Verify TLS handshake state machine cannot be forced into invalid state
  - [x] ✅ Server: `START -> WAIT_FINISHED -> CONNECTED`; default returns `INTERNAL_ERROR` alert
  - [x] ✅ HelloRetryRequest: state resets to `START` with `hello_retry=1`; second retry rejected (line 315-318)
  - [x] ✅ Each state handler validates expected message type

- [x] **TLS-003**: Verify extension parsing handles unknown/duplicate extensions safely
  - [x] ✅ ClientHello unknown extensions: silently skipped (fd_tls_proto.c:142)
  - [x] ✅ ServerHello unknown extensions: rejected with `ILLEGAL_PARAMETER`
  - [x] ⚠️ Duplicate extensions: last-wins silently (non-compliant with RFC 8446 but not exploitable)

- [x] **TLS-004**: Verify key schedule is correct and isolated from attacker influence
  - [x] ✅ All `fd_tls_hkdf_expand_label` calls use hardcoded label strings and 32-byte transcript hashes
  - [x] ✅ Max `info` buffer usage ~55 bytes, well within 139-byte buffer
  - [x] ✅ Only supports Ed25519 + X25519 + AES-128-GCM-SHA256, reducing attack surface

- [x] **TLS-005**: Verify ASN.1 parser cannot be crashed by malformed certificates
  - [x] ✅ Ed25519 raw key: exact 12-byte prefix + `sz == 44` check (fd_tls_asn1.c:16-30)
  - [x] ✅ X.509: `fd_x509_mock_pubkey` pattern-matches entire template, returns NULL on any mismatch
  - [x] ✅ Certificate chain: `FD_TLS_SKIP_FIELD` macros bounds-check via serde framework

---

## 3. Gossip Protocol

🔴 **HIGH**

**Files:** `src/flamenco/gossip/fd_gossip.c`, `src/flamenco/gossip/fd_gossip.h`, `src/discof/gossip/fd_gossip_tile.c`, `src/discof/gossip/fd_gossvf_tile.c`

### 3.1 Message Parsing

- [x] **GOSS-001**: Verify gossip message deserialization bounds-checks all length fields
  - [x] ✅ Packet size clamped to 1232 bytes (fd_gossip_message.c:644); all wire-read lengths bounded by payload exhaustion
  - [x] ✅ `READ_BYTES`, `READ_U64`, `SKIP_BYTES` macros check `n <= payload_sz` before proceeding
  - [x] ✅ Trailing bytes rejected (line 657): `return !*payload_sz`

- [x] **GOSS-002**: Verify `PullRequest` filter processing resists CPU exhaustion
  - [x] ✅ `bits_cap` overflow-checked: `__builtin_mul_overflow(bits_cap, 8UL, &dummy)` (line 537)
  - [x] ✅ `bits_len=0` explicitly rejected (line 541); `keys_len=0` returns match-all (sends nothing)
  - [x] ✅ `mask_bits` validated `< 64` in gossvf (line 783)

- [x] **GOSS-003**: Verify `PushMessage` CRDS entry count is bounded
  - [x] ✅ Each value >= 68 bytes (sig + tag); max 17 values in 1232-byte packet
  - [x] ✅ Fixed-size stack array `FD_GOSSIP_MESSAGE_MAX_CRDS = 17` - no unbounded allocation

### 3.2 Vote and Identity Handling

- [x] **GOSS-004**: Verify gossip vote transactions are not double-spend vectors
  - [x] ✅ In Firedancer topology, gossip votes flow through verify tile (signature verified) before reaching dedup
  - [x] ✅ All CRDS values including votes are signature-verified in gossvf tile

- [x] **GOSS-005**: Verify ContactInfo validation
  - [x] ✅ Gossip socket: `check_addr` rejects null, multicast, private (unless `allow_private_address`)
  - [x] ✅ Duplicate IPs rejected (fd_gossip_message.c:393-400); socket key uniqueness enforced (403-407)
  - [x] ✅ Port overflow checked with `__builtin_add_overflow` (line 421)
  - [x] ✅ Shred version filtered by gossvf against local shred version

- [x] **GOSS-006**: Verify wallclock timestamp validation is strict enough
  - [x] ✅ `WALLCLOCK_MAX_MILLIS = 10^15` enforced during deserialization via `READ_WALLCLOCK`
  - [x] ✅ Drift: +-15 seconds enforced in gossvf for push, pull_request, pull_response values
  - [x] ⚠️ `FD_MILLI_TO_NANOSEC` integer overflow for large wallclock values, but no security impact (CRDS values must be signed by originator)

### 3.3 Rate Limiting and Peer Management

- [x] **GOSS-007**: Verify unauthenticated gossip messages cannot exhaust peer table
  - [x] ✅ Ping/pong verification required for unstaked peers before processing pull requests or accepting ContactInfo
  - [x] ✅ Staked peers bypass ping check, but ContactInfo must be signed by stated origin key
  - [x] ✅ Outbound data budget rate-limits responses

- [x] **GOSS-008**: Verify ping/pong protocol cannot be used for amplification
  - [x] ✅ Ping = 132 bytes, pong = 132 bytes - no size amplification
  - [x] ✅ Pull request amplification mitigated by ping/pong verification for unstaked peers + signature requirement
  - [x] ✅ Outbound data budget rate-limits all gossip responses

---

## 4. Transaction Processing Pipeline

🟣 **CRITICAL**

**Files:** `src/disco/verify/fd_verify_tile.c`, `src/disco/dedup/fd_dedup_tile.c`, `src/disco/pack/fd_pack.c`, `src/disco/pack/fd_pack_tile.c`, `src/disco/pack/fd_pack_cost.h`

### 4.1 Signature Verification Tile

- [x] **TXN-001**: Verify parse failure drops transaction, not forwards with zero `txn_t_sz`
  - [x] ✅ `fd_verify_tile.c:131-135`: explicit `if(!txnm->txn_t_sz) return;` - early return prevents forwarding
  - [x] ✅ `fd_stem_publish()` never called on parse failure; dedup never sees uninitialized data
  - [x] ✅ Bundle failure tracked via `ctx->bundle_failed = 1`

- [x] **TXN-002**: Verify batch ED25519 verification rejects all transactions on batch failure
  - [x] ✅ fd_ed25519_verify_batch_single_msg (fd_ed25519_user.c:232-310) verifies all
    sigs for a single txn message. Any failure returns error -> entire txn rejected.
    No selective per-signature rejection. Batch limit #define MAX 16, txn max 12.
  - [x] ✅ Low-order points: fd_ed25519_affine_is_small_order (fd_curve25519.h:88-118)
    rejects all 8 torsion points for both pubkey (ERR_PUBKEY) and R (ERR_SIG).
    Cofactorless verification + explicit small-order rejection matches Agave/Dalek 2.x.
  - [x] ✅ Non-canonical y >= p: NOT checked, matching Agave Dalek 2.x behavior.
    Negative zero (x=0, sign bit set): accepted, matching Dalek. Code comments at
    fd_ed25519_user.c:173 acknowledge this is intentional Agave compatibility.
  - [x] ✅ All-zero signature: scalar S=0 passes scalar validation (valid in [0,L))
    but R point decompresses to small-order point -> rejected by small-order check.
  - [x] ✅ Invalid pubkey (not on curve): fd_ed25519_point_frombytes returns NULL,
    caught at fd_ed25519_user.c:276-280 (ERR_PUBKEY vs ERR_SIG distinguished).
  - [x] ✅ sig_cnt > acct_cnt: prevented by parser (fd_txn_parse.c:113)

- [x] **TXN-003**: Verify transaction size limits enforced before processing
  - [x] ✅ QUIC path: `initial_rx_max_stream_data = FD_TXN_MTU` (fd_quic_tile.c:580) -
    stream-level flow control limits to 1232 bytes. TPU reassembly checks at
    fd_tpu_reasm.c:215-218 reject overflow. Verify tile defensive check at line 80-81.
  - [x] ✅ Gossip path: fd_verify_tile.c:90-94 reads untrusted `transaction_len` -
    known issue #9160 ("untrusted txn length in verify tile"). Excluded from scope.
    Subsequent fd_txn_parse enforces FD_TXN_MTU.

### 4.2 Deduplication Tile

- [x] **TXN-004**: Verify tcache (signature cache) cannot be poisoned by crafted signatures
  - [x] ✅ Hash: xxhash-r39 with randomized seed (fd_rng_secure at privileged_init).
    64-bit output space. Preimage attack infeasible without breaking xxhash.
  - [x] ✅ Eviction: FIFO ring buffer (fd_tcache.h:373-404). Depth ~4M (verify) / ~67M
    (dedup). Forcing eviction requires inserting `depth` valid signed transactions -
    impractical due to ED25519 verification cost.
  - [x] ✅ False positive rate: birthday paradox gives ~1/2^20 for verify cache,
    ~1/2^12 for dedup cache. A collision silently drops the legitimate txn (no error).
    Very low probability, acceptable for the use case. Not exploitable in practice
    because attacker would need to predict the randomized seed to target a specific txn.

- [x] **TXN-005**: Verify gossip votes entering dedup tile via separate path are correctly handled
  - [x] ✅ `IN_KIND_GOSSIP` path (`gossip_dedup` link) only wired in Frankendancer topology (`fdctl/topology.c`), NOT in Firedancer topology
  - [x] ✅ In Firedancer, gossip votes flow gossip -> verify -> dedup as `IN_KIND_VERIFY` (already parsed/verified)

### 4.3 Pack Tile

- [x] **TXN-006**: Verify cumulative block compute cost cannot overflow or wrap
  - [x] ✅ `cu_limit = max_cost_per_block - cumulative_block_cost` computed before scheduling; txn rejected if `compute_est > cu_limit`
  - [x] ✅ `max_cost_per_block` bounded at 100M, `compute_est` bounded by `FD_PACK_MAX_TXN_COST` (~1.57M) - overflow impossible
  - [x] ✅ Rebate subtraction from bank tile is trusted (tile-to-tile, out of scope)

- [x] **TXN-007**: Verify write-lock cost accounting matches actual execution cost
  - [x] ✅ Per-account `total_cost` bounded by `max_write_cost_per_acct` (40M max) - check at line 1916 prevents exceeding
  - [x] ✅ Bundle `carried_cost` is `uint`, max ~7.8M for 5-txn bundle - well within range
  - [x] ✅ No overflow possible in per-account accumulation

- [x] **TXN-008**: Verify fee priority ordering cannot be manipulated to front-run or censor
  - [x] ✅ Cross-multiplication used (`COMPARE_WORSE` macro at line 201) avoids division entirely
  - [x] ✅ `compute_est` is always >= `FD_PACK_MIN_TXN_COST` (1020) for inserted transactions
  - [x] ✅ Float score at line 1146 uses `compute_est` which is always positive

- [x] **TXN-009**: Verify ALT (Address Lookup Table) account loading is bounds-checked
  - [x] ✅ fd_alut.h:245-257: writable and readonly indices checked against
    `active_addresses_len`. Returns INVALID_ADDRESS_LOOKUP_TABLE_INDEX on OOB.
    Max entries capped at FD_ADDRLUT_MAX_ENTRIES=512.
  - [x] ✅ Readonly/writable correctly separated: writable at
    `out_accts_alt[rw_indir_cnt++]`, readonly at offset `addr_table_adtl_writable_cnt`.
    No misclassification path.
  - [x] ✅ Duplicates allowed and tested (test_runtime_alut.c:1845-1910). Expected
    behavior matching Solana spec.

- [x] **TXN-010**: Verify block packing respects slot-wide compute limit, not just per-microblock
  - [x] ✅ fd_pack.c:2302-2305: `cu_limit = max_cost_per_block - cumulative_block_cost`
    computed BEFORE each microblock. Each txn checked at line 2325 against remaining
    capacity. Cumulative cost tracked at line 2498. 48M CU per slot
    (FD_PACK_MAX_COST_PER_BLOCK_LOWER_BOUND, fd_pack_cost.h:194). Vote costs tracked
    separately (36M limit). Per-account write cost capped at 12M. Cannot exceed slot
    limit via multiple microblocks.
  - [ ] Pack tile does not track cross-microblock cumulative slot cost

---

## 5. sBPF VM - Core Execution

🟣 **CRITICAL**

**Files:** `src/flamenco/vm/fd_vm_interp_core.c`, `src/flamenco/vm/fd_vm_private.h`, `src/flamenco/vm/fd_vm.c`

### 5.1 Memory Translation

- [x] **VM-001**: Verify memory region binary search handles zero-region edge case
  - [x] ✅ Fixed on v1.0: `fd_vm_private.h:401` guards `input_mem_regions_cnt==0` before binary search
  - [x] ✅ `fd_vm_mem_cfg` (line 228) also handles zero-count by zeroing TLB entries
  - [x] ✅ Binary search uses saturating arithmetic (`fd_ulong_sat_sub`) consistently

- [x] **VM-002**: Verify overlapping memory region ranges handled correctly
  - [x] ✅ Binary search finds largest `vaddr_offset <= target`, bounds-checked with `bytes_in_region`
  - [x] ✅ Region index clamped to [0,5] via `fd_ulong_min` in `FD_VADDR_TO_REGION`
  - [x] ✅ `vaddr_offset + address_space_reserved` bounded to ~5 GiB, no overflow

- [x] **VM-003**: Verify virtual-to-host address translation for all region types
  - [x] ✅ Stack gap handling: only start address checked against gap boundaries (matches Agave)
  - [x] ✅ `region_sz` stored as `uint` but max is `FD_RUNTIME_ACC_SZ_MAX` (10 MiB) - no truncation
  - [x] ✅ Write permission enforced at line 429; `FD_VM_MEM_HADDR_ST_WRITE_UNCHECKED` exists but unused in production

- [x] **VM-004**: Verify `text_off` alignment validation before instruction fetch
  - [x] ✅ `text_off` not explicitly aligned-checked, but CALLX handler divides by 8 and bounds-checks against `text_cnt` - underflow produces huge value that always fails
  - [x] ✅ SBPF V3: `text_off` forced to 0 (`fd_vm.c:621`)

### 5.2 Instruction Dispatch

- [x] **VM-005**: Verify all BPF opcodes handled in interpreter switch (no fall-through to undefined)
  - [x] ✅ Jump table (`fd_vm_interp_jump_table.c`) dispatches all opcodes; invalid ones go to `sigill`/`siginv`
  - [x] ✅ Wide instruction (LDDW/two-instruction) handled atomically with pc+=2
  - [x] ✅ Jump target checked: `pc >= text_cnt` → `sigtext` fault

- [x] **VM-006**: Verify signed division edge case: `INT64_MIN / -1` handled
  - [x] ✅ 32-bit: `((int)reg_dst==INT_MIN) & ((int)reg_src==-1)` → `sigfpeof` (line ~1019)
  - [x] ✅ 64-bit: `((long)reg_dst==LONG_MIN) & ((long)reg_src==-1L)` → `sigfpeof` (line ~1062)
  - [x] ✅ Zero divisor: every div/mod checks `if(!reg_src) goto sigfpe`

- [x] **VM-007**: Verify shift amount masking is correct per sBPF spec
  - [x] ✅ 64-bit shifts: `FD_RUST_ULONG_WRAPPING_SHL(a,b)` masks `b & 63`
  - [x] ✅ 32-bit shifts: `FD_RUST_UINT_WRAPPING_SHL(a,b)` masks `b & 31`
  - [x] ✅ Matches Rust wrapping semantics (`u64::wrapping_shl`, etc.)

- [x] **VM-008**: Verify compute unit metering prevents infinite loops
  - [x] ✅ CU checked at branch boundaries via `ic_correction`: `if(ic_correction > cu) goto sigcost`
  - [x] ✅ Linear segments accumulate instruction count, deducted at next branch - cannot bypass
  - [x] ✅ CU is `ulong`; subtraction uses `cu -= fd_ulong_min(ic_correction, cu)` (saturating) at halt

### 5.3 Stack and Call Frames

- [x] **VM-009**: Verify call stack depth limit enforced correctly
  - [x] ✅ `++frame_cnt >= frame_max` (64, `FD_VM_STACK_FRAME_MAX`) → `sigstack` fault (line 293)
  - [x] ✅ Return from depth-0: `if(!frame_cnt) goto sigexit` - clean program exit (line 852)
  - [x] ✅ Shadow stack stores r6-r10, pc for each frame; restored on return

- [x] **VM-010**: Verify stack frame isolation between programs
  - [x] ✅ Stack memory divided into 64 frames of 4096 bytes each (`FD_VM_STACK_FRAME_SZ`)
  - [x] ✅ Stack pointer set per frame; VM memory translation validates bounds

---

## 6. sBPF VM - Syscalls and CPI

🟣 **CRITICAL**

**Files:** `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c`, `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c`, `src/flamenco/vm/syscall/fd_vm_syscall.c`, `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c`

### 6.1 CPI Validation

- [x] **CPI-001**: Verify duplicate account index detection in CPI account list
  - [x] ✅ Dead code at `fd_vm_syscall_cpi.c:115` is unreachable but harmless - dedup logic works correctly
  - [x] ✅ Duplicate accounts detected by scanning `deduplicated_instruction_accounts[j].index_in_transaction`
  - [x] ✅ Flags (is_signer, is_writable) correctly unioned for duplicates

- [x] **CPI-002**: Verify account data length is snapshot atomically before use in CPI
  - [x] ✅ NOT a real TOCTOU: VM is single-threaded, BPF program suspended during entire syscall handler
  - [x] ✅ Shared `ref_to_len_in_vm` aliasing bug was previously found and FIXED (check at line 630 catches stale length)
  - [x] ✅ Direct mapping case: `serialized_data` set to NULL (line 455), dangerous memcpy path not taken

- [x] **CPI-003**: Verify account owner validation on all CPI paths
  - [x] ✅ `fd_borrowed_account_set_owner` enforces: only current owner can change, account writable, data zeroed
  - [x] ✅ `fd_vm_prepare_instruction` (lines 150-163): writable/signer privilege checks match Agave
  - [x] ✅ No owner validation gaps found

- [x] **CPI-004**: Verify maximum CPI depth enforced
  - [x] ✅ `FD_MAX_INSTRUCTION_STACK_DEPTH = 5` enforced in `fd_txn_ctx_push` (fd_executor.c:965)
  - [x] ✅ Stack size incremented at push, decremented in `fd_txn_ctx_pop` on both success and error paths
  - [x] ✅ No underflow or bypass possible

- [x] **CPI-005**: Verify signers set correctly propagated through CPI
  - [x] ✅ PDA signers derived with caller's program ID; `FD_CPI_MAX_SIGNER_CNT = 16` enforced (line 757)
  - [x] ✅ `fd_vm_prepare_instruction` checks callee signers are either caller signers or PDA-derived
  - [x] ✅ Signer seeds properly translated and validated

### 6.2 Memory and Logging Syscalls

- [x] **CPI-006**: Verify `sol_memcpy_`, `sol_memmove_`, `sol_memset_` reject overlapping src/dst when required
  - [x] ✅ `memcpy`: checks overlap via `FD_VM_MEM_CHECK_NON_OVERLAPPING` (line 400)
  - [x] ✅ `memmove`: does NOT check overlap (correct - memmove allows overlap)
  - [x] ✅ `memset(sz=0)`: returns success immediately (line 473); CU charged via `FD_VM_CU_MEM_OP_UPDATE`

- [ ] **CPI-007**: Verify `sol_log_` and `sol_log_data` bounded by log collector capacity
  - [ ] Log message size limit (10KB per transaction) enforced
  - [ ] Log calls beyond limit truncated or rejected, not silently dropped
  - [ ] `sol_log_64` with large hex values: buffer formatting overflow
  - **Note:** Lower priority - log collector bugs unlikely to cause fund loss

### 6.3 Crypto Syscalls

- [x] **CPI-008**: Verify `sol_sha256`, `sol_keccak256` handle zero-length and huge inputs
  - [x] ✅ `vals_len` bounded by `FD_VM_SHA256_MAX_SLICES = 20000` (fd_vm_base.h:264)
  - [x] ✅ Per-slice CU cost: `fd_ulong_sat_mul(BYTE_COST, val_len/2)` - saturating, no overflow
  - [x] ✅ Each slice address translated via `FD_VM_MEM_SLICE_HADDR_LD` with bounds check

- [ ] **CPI-009**: Verify `sol_secp256k1_recover` handles all error cases
  - [ ] Recovery ID out of range (0-3 valid, others must return error)
  - [ ] Invalid signature (not on curve) returned as error, not zeroed key
  - [ ] Signature is all-zeros (identity point)

- [ ] **CPI-010**: Verify `sol_alt_bn128_*` (if implemented) handles field element validation
  - [ ] Points not on curve accepted
  - [ ] Field elements >= prime modulus accepted
  - [ ] Identity point handling for group operations

### 6.4 PDA Derivation

- [x] **CPI-011**: Verify PDA derivation matches Agave for all edge cases
  - [x] ✅ `seeds_cnt > FD_VM_PDA_SEEDS_MAX (16)` rejected (fd_vm_syscall_pda.c:35)
  - [x] ✅ `seed_sz > FD_VM_PDA_SEED_MEM_MAX (32)` rejected (line 52)
  - [x] ✅ `seeds_cnt + bump_seed > 16` checked (line 44) - accounts for bump seed
  - [x] ✅ `try_find_program_address` iterates bump 255..0, checking on-curve rejection per nonce (lines 286-294)

---

## 7. ELF / sBPF Loader

🟣 **CRITICAL**

**Files:** `src/ballet/sbpf/fd_sbpf_loader.c`, `src/ballet/sbpf/fd_sbpf_loader.h`, `src/ballet/elf/fd_elf64.h`, `src/flamenco/runtime/program/fd_bpf_loader_program.c`

- [x] **ELF-001**: Verify ELF header validation is complete before processing sections
  - [x] ✅ `e_machine == FD_ELF_EM_BPF` (247) enforced at `fd_sbpf_loader.c:761`
  - [x] ✅ `e_phoff == sizeof(fd_elf64_ehdr)` enforced; `program_header_table_end > bin_sz` checked (line 770)
  - [x] ✅ `e_phentsize == sizeof(fd_elf64_phdr)` enforced; `e_ehsize == sizeof(fd_elf64_ehdr)` enforced
  - [x] ✅ `FD_ELF_CLASS_64` (64-bit) and `FD_ELF_DATA_LE` (little-endian) enforced

- [x] **ELF-002**: Verify section header table is fully bounds-checked
  - [x] ✅ `sh_offset + sh_size` uses `fd_ulong_sat_add` (line 84) - saturating addition prevents overflow
  - [x] ✅ SHT_NOBITS returns NULL range with zeroed lo/hi (line 80-82) - no file read
  - [x] ✅ Relocation table: `offset + size` overflow-checked with `__builtin_uaddl_overflow` (line 1262)

- [x] **ELF-003**: Verify `.text` section processing cannot read outside file
  - [x] ✅ `.text` section range checked: `fd_ulong_sat_add(sh_text->sh_addr, sh_text->sh_size)` bounded (line 701)
  - [x] ✅ All section accesses via `fd_sbpf_range_contains` against file bounds
  - [x] ✅ Duplicate sections handled by SBPF program header validation

- [x] **ELF-004**: Verify relocation processing is bounded
  - [x] ✅ Relocation count: `dt_rel_sz / sizeof(fd_elf64_rel)` - divisor is constant (16), no div-by-zero
  - [x] ✅ `dt_rel_sz % sizeof(fd_elf64_rel) != 0` rejected (line 1268)
  - [x] ✅ `offset + size > bin_sz` checked with overflow protection (line 1262-1269)
  - [x] ✅ Each relocation target `r_offset` bounds-checked against `elf_sz` in handler functions

- [x] **ELF-005**: Verify `.rodata` sections cannot be used to forge executable code
  - [x] ✅ `.rodata` at `FD_SBPF_MM_RODATA_START (0x0)` with `PF_R` flag (read-only); `.text` at `FD_SBPF_MM_BYTECODE_START (0x100000000)` with `PF_X` (execute-only)
  - [x] ✅ VM memory translation enforces permissions per-region (write-only for writable regions)
  - [x] ✅ Program headers validated against expected virtual addresses and flags (line 788-789)

- [x] **ELF-006**: Verify dynamic symbol table processing
  - [x] ✅ String table access bounds-checked: `memchr` for null terminator within `[sh_offset, sh_offset+sh_size)` (line 287)
  - [x] ✅ Missing null terminator returns `FD_SBPF_ELF_PARSER_ERR_STRING_TOO_LONG` (line 289)
  - [x] ✅ Syscall hash collision: `fd_sbpf_syscalls_query(pc_hash)` checked before calldest registration (line 354)

- [ ] **ELF-007**: Verify upgrade BPF loader program correctly validates new ELF on deploy
  - [ ] New program ELF size exceeds account data limit
  - [ ] Deploying a program over an active (in-execution) program account
  - [ ] Partially uploaded program (Write instruction): offset+size overflow in account data

---

## 8. Runtime - Built-in Programs

🟣 **CRITICAL**

**Files:** `src/flamenco/runtime/program/fd_system_program.c`, `src/flamenco/runtime/program/fd_vote_program.c`, `src/flamenco/runtime/program/fd_bpf_loader_program.c`, `src/flamenco/runtime/program/fd_loader_v4_program.c`, `src/flamenco/runtime/program/fd_compute_budget_program.c`, `src/flamenco/runtime/program/fd_precompiles.c`

### 8.1 System Program

- [x] **PROG-001**: Verify `CreateAccount` cannot create account with lamports < rent-exempt minimum
  - [x] ✅ No rent-exemption check at creation time - matches Agave behavior (rent enforced later)

- [x] **PROG-002**: Verify `Transfer` cannot produce lamport imbalance (total conserved)
  - [x] ✅ `fd_borrowed_account_checked_sub_lamports` / `checked_add_lamports` use `fd_ulong_checked_*` - overflow/underflow returns error
  - [x] ✅ Transfer to self: handled by dropping `from` borrow before re-borrowing as `to`

- [x] **PROG-003**: Verify `CreateAccountWithSeed` seed length validation
  - [x] ✅ Seed length capped at `MAX_SEED_LEN = 32` in `fd_pubkey_create_with_seed` (fd_pubkey_utils.c:16)

- [x] **PROG-004**: Verify `Assign` cannot change account owner to non-existing program
  - [x] ✅ No executability check on new owner - matches Agave behavior

- [x] **PROG-005**: Verify nonce account operations (advance, withdraw, authorize)
  - [x] ✅ Advance in Uninitialized state: returns `FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA` (line 232)
  - [x] ✅ Withdrawal: rent-exempt minimum checked at line 404-417 with saturating overflow check
  - [x] ✅ Authorization: signer and state validated; `FD_LOG_CRIT` on unknown discriminants (not remotely triggerable)

### 8.2 Vote Program

- [x] **PROG-006**: Verify vote state deserialization handles all versions correctly
  - [x] ✅ Unknown discriminants return NULL from `fd_vote_state_versioned_new` (fd_vote_codec.c:655) - propagated as clean error

- [x] **PROG-007**: Verify vote lockout computation doesn't overflow
  - [x] ✅ Confirmation count clamped to `MAX_LOCKOUT_HISTORY = 31` (line 630)
  - [x] ✅ `pow(2.0, n)` for n=0-31 is exact in IEEE 754 double precision
  - [x] ⚠️ Separate code path uses `1UL << confirmation_count` (fd_vote_utils.c:16) - consistent but duplicated

- [x] **PROG-008**: Verify `UpdateVoteState` instruction validation
  - [x] ✅ Slot ordering validated at lines 272-283 (`FD_VOTE_ERR_SLOTS_NOT_ORDERED`)
  - [x] ✅ Confirmation ordering (line 542-545), zero confirmations (526-527), lockout mismatches (546-549) all checked

- [x] **PROG-009**: Verify `Withdraw` from vote account respects minimum balance
  - [x] ✅ Rent-exempt minimum enforced at lines 1064-1076 with overflow check on addition (line 1070)

### 8.3 BPF Loader

- [ ] **PROG-010**: Verify BPF loader program instruction parsing bounds
  - [ ] `FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_FOOTPRINT` set to MTU - verify no OOB during decode
  - [ ] `Write` instruction: `offset + data.len > account.data.len` - OOB write into account

- [ ] **PROG-011**: Verify program deployment validates ELF before committing state
  - [ ] Finalize instruction: partially loaded program deployed without complete ELF
  - [ ] `Finalize` on account with zero bytes

- [ ] **PROG-012**: Verify program authority enforcement
  - [ ] Upgrade authority check: `None` vs `Some(pubkey)` confusion
  - [ ] Close instruction with wrong authority can drain program account
  - [ ] Two transactions racing to close and upgrade same program in same slot

### 8.4 Compute Budget Program

- [x] **PROG-013**: Verify compute budget instruction parsing
  - [x] ✅ Compute limit clamped: `fd_ulong_min(FD_MAX_COMPUTE_UNIT_LIMIT, compute_unit_limit)` (line 91)
  - [x] ✅ `SetComputeUnitLimit(0)` → CU budget = 0; first instruction fails immediately (matches Agave)
  - [x] ✅ Default calculation uses `fd_ulong_sat_add` / `fd_ulong_sat_mul` (line 63-64)

- [x] **PROG-014**: Verify heap size request is bounded
  - [x] ✅ `sanitize_requested_heap_size`: rejects `> FD_MAX_HEAP_FRAME_BYTES`, `< FD_MIN_HEAP_FRAME_BYTES`, non-aligned (line 70-71)
  - [x] ✅ Granularity check: `bytes % FD_HEAP_FRAME_BYTES_GRANULARITY != 0` rejected

### 8.5 Precompiles (secp256k1, ed25519)

- [x] **PROG-015**: Verify secp256k1 precompile instruction parsing
  - [x] ✅ `expected_data_size = sig_cnt * 11 + 1` checked against `data_sz` before access
  - [x] ✅ Offset fields validated: `(ulong)offset + (ulong)sz > data_sz` checked in `fd_precompile_get_instr_data` (line 113)
  - [x] ✅ `sig_cnt == 0` returns error (`PRECOMPILE_ERR_INSTR_DATA_SIZE`)

- [x] **PROG-016**: Verify ed25519 precompile handles all signature/pubkey configurations
  - [x] ✅ Instruction index: `index >= txn->instr_cnt` returns `PRECOMPILE_ERR_DATA_OFFSET` (line 101-102)
  - [x] ✅ `offset + sz > data_sz` bounds-checked for pubkey, signature, and message reads
  - [x] ✅ Edge case: `data_sz == 2 && data[0] == 0` returns success (matches Agave quirk)

---

## 9. Runtime Conformance (vs. Agave)

🟣 **CRITICAL**

**Files:** `src/flamenco/runtime/fd_executor.c`, `src/flamenco/runtime/fd_bank.c`, `src/flamenco/runtime/fd_runtime.c`, `src/flamenco/runtime/fd_hashes.c`

- [x] **CONF-001**: Verify fee calculation matches Agave exactly
  - [x] ✅ Execution fee: `5000 * total_num_signatures` (including precompile sigs); priority fee: `price * limit / 1M` (rounded up)
  - [x] ✅ Fee deducted in `fd_executor_validate_transaction_fee_payer` before instruction execution
  - [x] ✅ Fee burn: `execution_fees / 2` hardcoded (matches mainnet burn_percent=50)

- [x] **CONF-002**: Verify rent collection behavior matches Agave
  - [x] ✅ Rent collection handled at epoch boundary via partitioned rewards system
  - [x] ⚠️ Not deeply tested - requires runtime comparison testing

- [x] **CONF-003**: Verify bank hash computation matches Agave field-for-field
  - [x] ✅ SIMD-215 lthash: `sha256(sha256(prev_hash, sig_count, last_poh), lthash_2048)` (fd_hashes.c:51-74)
  - [x] ✅ Account lthash: Blake3 of (lamports, data, executable, owner, pubkey) with 2048-byte output
  - [x] ✅ Blockhash queue: `FD_BLOCKHASHES_MAX = 301` matches Agave's `MAX_RECENT_BLOCKHASHES + 1`

- [x] **CONF-004**: Verify epoch boundary handling matches Agave
  - [x] ✅ Ordering: feature activations -> warmup/cooldown -> stake delegations -> partitioned rewards -> leader schedule
  - [x] ✅ Feature prepopulation for upcoming epoch at `fd_features_prepopulate_upcoming` (fd_runtime.c:875)

- [x] **CONF-005**: Verify sysvars are updated at correct timing
  - [x] ✅ Pre-execute: fee rate governor, clock, slot hashes, last restart slot
  - [x] ✅ Freeze-time: recent blockhashes, slot history, fees settled, incinerator cleaned

- [x] **CONF-006**: Verify account state snapshots match after executing same transactions
  - [x] ⚠️ Requires runtime comparison testing against Agave on same blocks - not feasible in static analysis

- [x] **CONF-007**: Verify blockhash age validation matches Agave
  - [x] ✅ Age validation: `FD_SYSVAR_RECENT_HASHES_CAP = 150` as max_age with `age <= max_age`
  - [x] ✅ Durable nonce: falls through to nonce validation if blockhash not in queue; SIMD-242 `require_static_nonce_account` present
  - [x] ⚠️ Nonce transactions intentionally NOT inserted into status cache (documented divergence from Agave)

- [x] **CONF-008**: Verify stake reward distribution matches Agave
  - [x] ✅ Partitioned rewards distributed every slot via `fd_distribute_partitioned_epoch_rewards`
  - [x] ⚠️ Requires runtime comparison testing for exact reward amounts

---

## 10. Proof of History

🔴 **HIGH**

**Files:** `src/discof/poh/fd_poh.c`, `src/discof/poh/fd_poh_tile.c`

- [x] **POH-001**: Verify PoH state machine transitions handle all message types from replay tile
  - [x] ✅ `returnable_frag` mechanism: REPLAY messages deferred while leader bank exists (line 157); EXECLE deferred while no bank (155)
  - [x] ✅ Messages processed serially - no concurrent state transitions

- [x] **POH-002**: Verify PoH reset handling cannot corrupt internal hash state
  - [x] ✅ Reset deferred by `returnable_frag` while leader bank active
  - [x] ✅ State machine guards prevent interleaving of reset and mixin

- [x] **POH-003**: Verify mixin (transaction entry hash) incorporated correctly
  - [x] ✅ `fd_poh1_mixin` (line 700): if all txns failed, microblock skipped (no hash/tick)
  - [x] ✅ `microblocks_lower_bound` still incremented to maintain accounting with pack

- [x] **POH-004**: Verify PoH completion message to replay is correct
  - [x] ✅ Slot boundary at `hashcnt == hashcnt_per_slot` (line 572-574)
  - [x] ✅ `fd_poh_advance` caps `target_hashcnt` to `next_tick_hashcnt` (line 550) - at most one tick per call

- [x] **POH-005**: Verify hash count arithmetic cannot overflow
  - [x] ✅ Mainnet: `64 * 62500 = 4,000,000` - well within `ulong` range
  - [x] ⚠️ `hashes_per_tick = 0` only in dev "low power" mode - causes modulo-by-zero (not remotely exploitable)
  - [x] ✅ `leader_slot_start_ns` uninitialized but clamped by `[min_hashcnt, restricted_hashcnt]` - timing issue only

---

## 11. Shred Tile & FEC Resolver

🔴 **HIGH**

**Files:** `src/disco/shred/fd_shred_tile.c`, `src/disco/shred/fd_fec_resolver.c`, `src/disco/shred/fd_shredder.c`, `src/disco/shred/fd_shred_dest.c`

- [ ] **SHRED-001**: Verify FEC set memory management prevents use-after-free
  - [ ] `fd_fec_resolver.h`: `partial_depth` and `complete_depth` guarantee memory not reused
  - [ ] FEC set freed before all in-flight references resolved
  - [ ] Concurrent FEC completion and eviction race

- [x] **SHRED-002**: Verify shred signature verification covers full shred content
  - [x] ✅ Signature covers Merkle tree root hash (32 bytes), not raw shred data
  - [x] ✅ Merkle leaf = hash of shred content (header + data, excluding signature) via `fd_bmtree_commitp_insert_with_proof` (line 649)
  - [x] ✅ Root verified via `fd_ed25519_verify(root, 32, sig, leader_pubkey)` (line 657-662)

- [ ] **SHRED-003**: Verify shred index bounds checking
  - [ ] `shred_idx >= data_shred_cnt`: coding shred presented as data shred
  - [ ] `fec_set_idx` uniqueness within a slot: same FEC set index with different data
  - [ ] `last_in_slot` flag on non-last shred

- [x] **SHRED-004**: Verify Merkle proof verification completeness
  - [x] ✅ Merkle tree depth = 7 layers (`FD_SHRED_MERKLE_LAYER_CNT`), nodes = 20 bytes
  - [x] ✅ Proof verified on first shred of FEC set (lines 602-662); subsequent shreds reuse verified tree
  - [x] ✅ `fd_bmtree_commitp_insert_with_proof` verifies each node in the proof path

- [x] **SHRED-005**: Verify Turbine retransmit does not amplify traffic
  - [x] ✅ Fanout capped at 200 (`DATA_PLANE_FANOUT`, fd_shred_tile.c:916)
  - [x] ✅ Tree structure: position determines forwarding targets; bottom-of-tree validators send nothing
  - [x] ✅ `fd_shred_dest_compute_children` enforces fanout-constrained forwarding (line 1002)

- [x] **SHRED-006**: Verify stake-weighted retransmit neighbor selection
  - [x] ✅ `fd_wsample` initialized with `stake_lamports` weights (fd_shred_dest.c:104-107)
  - [x] ✅ CHACHA RNG seeded per-shred with deterministic hash, ensuring reproducible selection
  - [x] ✅ Self-forwarding prevented via `fd_wsample_remove_idx` (line 289)

---

## 12. Shred Reassembly (Reasm)

🔴 **HIGH**

**Files:** `src/discof/reasm/fd_reasm.c`, `src/discof/reasm/fd_reasm_private.h`

- [ ] **REASM-001**: Verify CMR (Chained Merkle Root) overwrite validation
  - [ ] `fd_reasm.c:overwrite_invalid_cmr()`: parent slot lookup without cryptographic verification
  - [ ] Attacker crafts shreds with invalid CMR matching a valid parent slot hash
  - [ ] Blocks appear chained but CMR does not cryptographically bind them

- [ ] **REASM-002**: Verify FEC set completion does not read beyond allocated memory
  - [ ] Pool element allocation: `fec_max` bounds enforced before access
  - [ ] Orphaned FEC sets consuming pool entries indefinitely without eviction

- [ ] **REASM-003**: Verify ancestry map operations do not corrupt under concurrent access
  - [ ] `ancestry_footprint()` calculation vs actual insertions
  - [ ] Hash map chain traversal infinite loop via collisions

- [ ] **REASM-004**: Verify BFS traversal for subtree operations is bounded
  - [ ] `bfs_footprint(fec_max)`: BFS queue size vs actual subtree depth
  - [ ] Cycle in ancestry map (via crafted shreds) → infinite BFS loop

- [ ] **REASM-005**: Verify slot MR (Merkle Root) tracking handles equivocating leaders
  - [ ] Same slot with different MRs from two valid shreds
  - [ ] MR conflict detection and handling in reasm

---

## 13. Consensus - Tower BFT

🔴 **HIGH**

**Files:** `src/discof/tower/fd_tower_tile.c`, `src/choreo/tower/`, `src/discof/replay/fd_vote_tracker.c`

- [x] **TWR-001**: Verify vote lockout arithmetic is correct
  - [x] ✅ Max conf = `FD_TOWER_VOTE_MAX = 31`; `1UL << 31` is safe for `ulong`
  - [x] ✅ Tower tile validates received conf: `vote->conf > FD_TOWER_VOTE_MAX` rejected (line 777-784)
  - [x] ✅ Monotonicity of conf counts enforced (decreasing from tail to head)

- [x] **TWR-002**: Verify fork switch rules enforced correctly
  - [x] ✅ Threshold: `(double)threshold_stake / total_stake > 2.0/3.0` (line 654)
  - [x] ✅ Switch: `(double)switch_stake >= total_stake * 0.38` (line 562)
  - [x] ⚠️ Float arithmetic - covered by known issue #9157 (excluded)

- [x] **TWR-003**: Verify vote transaction construction for own validator
  - [x] ✅ Vote construction uses local tower state; expired votes filtered

- [x] **TWR-004**: Verify vote state reconciliation after snapshot load
  - [x] ✅ `fd_tower_reconcile()` (line 1000): replaces local tower with on-chain tower when behind
  - [x] ✅ Stale votes below local root correctly popped from head (line 1062-1068)

---

## 14. Consensus - Ghost Fork Choice

🔴 **HIGH**

**Files:** `src/choreo/ghost/fd_ghost.c`, `src/choreo/ghost/`

- [x] **GHOST-001**: Verify ghost pool auto-pruning prevents exhaustion
  - [x] ✅ Pool has `blk_max = pow2_up(max_live_slots) * 2` elements; blocks released on root advance
  - [x] ⚠️ `FD_TEST(blk_pool_free(pool))` at line 340 crashes if full - requires sustained root stall (liveness failure prerequisite)
  - [x] ✅ Not independently exploitable by remote attacker

- [x] **GHOST-002**: Verify stake weighting in ghost subtree calculation
  - [x] ✅ Stake overflow: `FD_LOG_CRIT` on overflow (lines 431-433, 448-450) - total SOL supply fits in `ulong`
  - [x] ✅ Voter pool bounded by VTR_MAX=2000 (FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT), pool capacity 2048

- [x] **GHOST-003**: Verify equivocating block handling
  - [x] ✅ Equivocating blocks tracked via LRU-based equivocation detection
  - [x] ✅ Ghost tree insert guards: tower tile checks `fd_ghost_query(ghost, &parent_block_id)` before insert (lines 991-1000)

- [x] **GHOST-004**: Verify ghost tree root advancement
  - [x] ✅ `fd_ghost_publish()` prunes nodes below new root; width tracking maintained
  - [x] ✅ Children reparented during publish

---

## 15. Consensus - Equivocation Detection

🔴 **HIGH**

**Files:** `src/choreo/eqvoc/fd_eqvoc.c`, `src/choreo/eqvoc/fd_eqvoc.h`

> **Note:** #9159 covers Merkle proof verification, stale FEC map entries, hardcoded indices, and missing slot validation. The following checks cover distinct aspects.

- [x] **EQVOC-001**: Verify pool exhaustion behavior (partial coverage by #9159)
  - [x] ✅ **Fixed**: LRU eviction now used for all bounded structures:
    - `dup_insert()` (line 474-478): evicts LRU on full pool
    - `fec_insert()` (line 498-501): evicts LRU on full pool
    - `prf_insert()` (line 526-531): evicts oldest per-voter proof
  - [x] ✅ No more `FD_LOG_ERR` crash on pool exhaustion

- [x] **EQVOC-002**: Verify equivocation proof verification does not trust chunk wallclock
  - [x] ✅ Chunk replacement is LRU-based (dlist ordering), NOT wallclock-based
  - [x] ✅ `fd_eqvoc_chunk_insert()` validates chunk_count, chunk_index, chunk_len, shred version, signature, and merkle root

- [x] **EQVOC-003**: Verify equivocation proofs are forwarded to gossip correctly
  - [x] ✅ Proofs detected via `fd_eqvoc_shred_insert` populate `chunks_out`
  - [x] ✅ Tower tile publishes as `FD_TOWER_SIG_SLOT_DUPLICATE` to gossip tile (line 655-675)

---

## 16. Replay Tile

🟣 **CRITICAL**

**Files:** `src/discof/replay/fd_replay_tile.c`, `src/discof/replay/fd_sched.c`, `src/discof/replay/fd_rdisp.c`

- [x] **REPLAY-001**: Verify block replay does not process out-of-ancestry-order FEC sets
  - [x] ✅ `insert_fec_set` (line 1850) validates parent bank existence and bank_seq consistency
  - [x] ✅ Out-of-order FEC detection at line 1897 drops FECs with stale `fec_set_idx`
  - [x] ✅ Dead parent propagation (lines 2002-2009) prevents executing on dead forks

- [x] **REPLAY-002**: Verify replay tile correctly handles leader slot transitions
  - [x] ✅ `returnable_frag` mechanism handles message ordering between replay and PoH
  - [x] ✅ State transitions guarded by proper bank existence checks

- [x] **REPLAY-003**: Verify untrusted data from repair tile properly validated before replay
  - [x] ✅ FEC sets go through reasm which validates Merkle proofs and signatures
  - [x] ✅ Already-finalized slots gracefully rejected via ancestry checks

- [x] **REPLAY-004**: Verify correct vote filtering and forwarding
  - [x] ✅ Vote tracker: bounded FIFO (512 entries) with hash map for O(1) lookup
  - [x] ✅ Duplicate signatures overwrite existing entries (no crash, no double-count)

- [x] **REPLAY-005**: Verify genesis hash validation on startup
  - [x] ✅ Genesis hash validated during snapshot loading

- [x] **REPLAY-006**: Verify execrp (execution result processing) messages validated
  - [x] ✅ `process_exec_task_done` validates bank existence (`FD_TEST(bank)`)
  - [x] ✅ Handles TXN_EXEC, TXN_SIGVERIFY, POH_HASH task types with proper bank state checks

---

## 17. Repair Protocol

🟠 **MEDIUM**

**Files:** `src/discof/repair/fd_repair.c`, `src/discof/repair/fd_repair_tile.c`, `src/discof/repair/fd_inflight.c`, `src/discof/repair/fd_policy.c`

> **Note:** #9166 covers FEC chain verification, forest cycles, repair flow assertions, stale orphan queue entries. Items below are distinct.

- [ ] **REPAIR-001**: Verify repair request rate limiting
  - [ ] No per-peer request rate limit: flood validator with repair requests from spoofed IPs
  - [ ] Global repair request rate: bounded or attacker can exhaust repair tile bandwidth
  - [ ] Repair response size proportional to request (no amplification)

- [ ] **REPAIR-002**: Verify repair response does not serve wrong shreds
  - [ ] Request for slot S, shred idx I: response includes correct shred
  - [ ] Response slot/index mismatch accepted by requesting validator (not verified)
  - [ ] Repair response triggers replay of arbitrary slot bypassing normal order

- [ ] **REPAIR-003**: Verify `fd_inflight.c` in-flight request tracking is bounded
  - [ ] Max in-flight requests per slot bounded
  - [ ] Expired in-flight requests properly evicted
  - [ ] Nonce validation: attacker crafts pong with matching nonce

- [ ] **REPAIR-004**: Verify repair ping/pong cannot be used for identity spoofing
  - [ ] Repair pong `from` field must match ping recipient's identity
  - [ ] SHA-256 pre-image in pong: `"SOLANA_PING_PONG" || ping_token` - token replay

---

## 18. Snapshot System

🔴 **HIGH**

**Files:** `src/discof/restore/`, `src/discof/restore/utils/fd_ssmanifest_parser.c`, `src/discof/restore/utils/fd_ssarchive.c`, `src/discof/restore/utils/fd_sshttp.c`, `src/discof/restore/utils/fd_slot_delta_parser.c`

> **Note:** #9176 covers a broad set of vinyl/snapshot/ssarchive issues. The following focus on distinct attack surfaces.

- [ ] **SNAP-001**: Verify snapshot HTTP client validates TLS certificate of snapshot server
  - [ ] `fd_sshttp.c`: HTTPS without certificate pinning → MITM attack injects malicious snapshot
  - [ ] HTTP redirect followed to untrusted host
  - [ ] Content-Length mismatch: response larger than declared

- [ ] **SNAP-002**: Verify snapshot hash verification before applying state
  - [ ] Snapshot hash from manifest verified against expected hash before loading accounts
  - [ ] Bank hash in manifest matches computed bank hash after loading
  - [ ] #9171 excluded "snapshot hash bypass" - confirm distinct variant not covered

- [ ] **SNAP-003**: Verify manifest parser handles malformed capitalization field
  - [ ] `STATE_CAPITALIZATION`: SOL total supply from snapshot larger than max supply
  - [ ] Capitalization underflow: reward distribution computation

- [ ] **SNAP-004**: Verify account data from snapshot bounded before loading into funk
  - [ ] Account `dlen` field in snapshot: `dlen > FD_ACC_DATA_MAX` accepted
  - [ ] Account `lamports + slot_delta_lamports` overflow during application

- [ ] **SNAP-005**: Verify archive (tar) parser is not susceptible to directory traversal
  - [ ] `fd_ssarchive.c`: archive path components with `..` or absolute paths
  - [ ] Symlinks in archive targeting outside expected directory
  - [ ] Archive with duplicate file entries: second overwrites first (which is legitimate)

- [ ] **SNAP-006**: Verify peer selector for snapshot download
  - [ ] `fd_sspeer_selector.c`: attacker gossips false snapshot hash+slot → snapshot discarded
  - [ ] Peer with manipulated `snapshot_hash` in gossip ContactInfo

---

## 19. Accounts Database (Funk)

🔴 **HIGH**

**Files:** `src/funk/fd_funk.c`, `src/funk/fd_funk_rec.c`, `src/funk/fd_funk_txn.c`, `src/funk/fd_funk_val.c`

- [x] **FUNK-001**: Verify transaction tree does not allow cycles
  - [x] ✅ XID uniqueness checked before insertion in `fd_funk_txn_prepare()` (line 67-70)
  - [x] ✅ Ancestor traversal bounded by `max_depth` (up to `FD_ACCDB_MAX_DEPTH_MAX = 8192`); `FD_LOG_CRIT` on overflow
  - [x] ✅ Cancel with children: `fd_accdb_txn_cancel_tree()` recurses depth-first; `FD_LOG_CRIT` if children exist on single cancel

- [x] **FUNK-002**: Verify record lookup under concurrent read-write workload
  - [x] ✅ EAGAIN loop bounded by chain-level versioning; conflicts rare (O(1) keys per chain)
  - [x] ✅ rwlock: simple spinlock, no fairness guarantee but critical sections very short
  - [x] ✅ Racesan annotations are zero-cost in production (testing-only instrumentation)

- [x] **FUNK-003**: Verify value allocation does not overflow workspace
  - [x] ✅ `fd_alloc_malloc_at_least()` returns NULL on failure; caller gets `FD_FUNK_ERR_MEM` (clean failure)
  - [x] ✅ val_sz truncation to 28 bits: validated by `FD_FUNK_HANDHOLDING` check (line 14)
  - [x] ✅ No double-free: documented single-writer-per-txn model; `FD_COMPILER_MFENCE` before free

- [x] **FUNK-004**: Verify transaction publish is atomic with respect to record visibility
  - [x] ✅ NOT atomic but carefully ordered: `last_publish` set atomically first, then records migrated one at a time
  - [x] ✅ Concurrent iteration during publish explicitly not supported (by design)
  - [x] ✅ Per-txn write lock drains concurrent readers before state transitions

- [x] **FUNK-005**: Verify `fd_funk_rec_map_t` hash table handles maximum fill factor
  - [x] ✅ Chain-based map (not open addressing) - no infinite probe loops possible
  - [x] ✅ Pool full: `fd_funk_rec_pool_acquire()` returns NULL with `FD_POOL_ERR_EMPTY`
  - [x] ✅ On x86_64: uses xxHash3 (via `FD_HAS_INT128`); HashDoS only affects non-x86_64 platforms

---

## 20. Vinyl KV Store

🔴 **HIGH**

**Files:** `src/vinyl/fd_vinyl.c`, `src/vinyl/fd_vinyl_base.c`, `src/vinyl/fd_vinyl_compact.c`, `src/vinyl/bstream/`, `src/vinyl/cq/`

> **Note:** #9176 covers a broad set of vinyl issues. Focus below on aspects likely not covered.

- [ ] **VINYL-001**: Verify vinyl read operations validate key size bounds
  - [ ] Key with length `ULONG_MAX` accepted without truncation
  - [ ] Key lookup in empty vinyl returns null vs crash

- [ ] **VINYL-002**: Verify vinyl compaction cannot corrupt live data
  - [ ] Compaction running concurrent with write operations
  - [ ] Compaction of partially-written records
  - [ ] Disk full during compaction: partial compaction + original both exist

- [ ] **VINYL-003**: Verify write-ahead log recovery after crash
  - [ ] Truncated WAL entry: recovery reads past end of log
  - [ ] WAL with duplicate entries: second application causes double-count
  - [ ] Corrupted WAL header: recovery crashes vs clean error

- [ ] **VINYL-004**: Verify vinyl block stream (`bstream/`) parsing
  - [ ] Block header length field overflow
  - [ ] Compressed block with decompressed size >> compressed size (zip bomb style)
  - [ ] Block checksum not verified before using data

---

## 21. IPC / Tango Messaging

🟠 **MEDIUM**

**Files:** `src/tango/mcache/fd_mcache.h`, `src/tango/dcache/fd_dcache.h`, `src/tango/tcache/fd_tcache.h`, `src/tango/cnc/fd_cnc.c`

- [x] **IPC-001**: Verify mcache TOCTOU race window is tolerated correctly
  - [x] ✅ Double-read: seq read (line 588), metadata copy (590), seq re-check (592)
  - [x] ✅ Overrun detected via `seq_found == seq_test && seq_diff >= 0` (line 595)
  - [x] ✅ Well-documented pattern with correct atomic ordering

- [ ] **IPC-002**: Verify dcache chunk index bounds validation
  - [ ] Chunk index from mcache metadata: `chunk > wmark` before `fd_chunk_to_laddr`
  - [ ] Chunk size field from metadata: `sz > FD_DCACHE_CHUNK_SZ` before copy

- [x] **IPC-003**: Verify tcache infinite loop protection
  - [x] ✅ Fill factor 25-50% enforced: `map_cnt >= depth+2`, guaranteeing >= 2 empty slots
  - [x] ✅ Linear probing terminates on NULL entry or matching tag (lines 281-295)
  - [x] ✅ `FD_TCACHE_SPARSE_DEFAULT=2` prevents pathological probe chains

- [x] **IPC-004**: Verify CNC PID reuse vulnerability
  - [x] ⚠️ Race exists: `kill(pid, 0)` then `CAS` at fd_cnc.c:176-184; code comments acknowledge it
  - [x] ✅ Requires local process creation - out of scope for remote-only attacker model
  - [x] ✅ Tile processes run in sandboxed namespaces with RLIMIT_NPROC restrictions

- [ ] **IPC-005**: Verify fseq flow control backpressure is respected
  - [ ] Producer ignores backpressure → overwrites consumer's in-flight messages
  - [ ] Consumer flow sequence never advances → producer stalls indefinitely (DoS)

---

## 22. Process Sandboxing

🔴 **HIGH**

**Files:** `src/util/sandbox/fd_sandbox.c`, per-tile `*.seccomppolicy` files

> **Note:** #9172 covers 32-bit seccomp argument bypass on x86_64. Items below are distinct.

- [x] **SAND-001**: Verify each tile's seccomp allowlist is minimal
  - [x] ✅ No `.seccomppolicy` file in `src/discof/` allows `execve`, `execveat`, `fork`, `clone`, `vfork`, `ptrace`
  - [x] ✅ All policies use whitelist approach; only specific operations on allowed FDs

- [x] **SAND-002**: Verify namespace isolation is enforced correctly
  - [x] ✅ User namespace created (fd_sandbox.c:651); other namespaces unshared (line 659)
  - [x] ✅ Filesystem pivoted to empty root (line 672)
  - [x] ✅ Controlling terminal detached (lines 613-614); session keyring replaced (line 609)

- [ ] **SAND-003**: Verify Landlock filesystem restrictions cover all writable paths
  - [ ] Tile working directory accessible write
  - [ ] `/tmp`, `/dev/shm` accessible when not needed
  - [ ] Landlock version detection falls back gracefully on kernels < 5.13

- [x] **SAND-004**: Verify no tile can acquire additional capabilities
  - [x] ✅ `PR_SET_NO_NEW_PRIVS = 1` set AFTER capability drops, BEFORE seccomp (line 684)
  - [x] ✅ SECBIT flags locked via `prctl(PR_SET_SECUREBITS)` (line 438)
  - [x] ✅ All capability bits dropped via `PR_CAPBSET_DROP` (line 445), ambient cleared (line 451), effective zeroed (line 450)

- [ ] **SAND-005**: Verify shared memory permissions per-tile are correct
  - [ ] QUIC tile: only read access to VERIFY tile's work area
  - [ ] Execle tile: cannot write to pack tile's shared memory
  - [ ] Gossip tile: cannot write to replay tile's bank state

- [x] **SAND-006**: Verify resource limits prevent fork bombs and memory exhaustion
  - [x] ✅ `RLIMIT_NPROC` configurable per-tile (not hardcoded to 0 but controlled by caller)
  - [x] ✅ Resource limits set before sandboxing (line 679)
  - [x] ✅ Seccomp blocks `fork`/`clone` regardless of RLIMIT_NPROC value

---

## 23. Cryptography (Ballet)

🔴 **HIGH**

**Files:** `src/ballet/ed25519/`, `src/ballet/sha256/`, `src/ballet/sha512/`, `src/ballet/aes/`, `src/ballet/ristretto255/`, `src/ballet/bmtree/`, `src/ballet/sbpf/`

- [ ] **CRYPT-001**: Verify ED25519 small-order public key rejection
  - [ ] Low-order points (8 points of order ≤ 8): explicitly rejected
  - [ ] Non-canonical public key encoding accepted (same point, different encoding)
  - [ ] All-zero public key accepted as valid

- [ ] **CRYPT-002**: Verify ED25519 batch verification correctly rejects invalid batches
  - [ ] Single invalid signature in batch: entire batch rejected
  - [ ] Batch size = 0: handled as success or error?
  - [ ] Batch verification with duplicate (sig, pubkey, msg) pairs

- [ ] **CRYPT-003**: Verify SHA-256 and SHA-512 correctness for edge cases
  - [ ] Empty message hash matches reference
  - [ ] Message length exactly 55, 56, 64 bytes (near block boundary)
  - [ ] Multi-block message with length encoding overflow

- [ ] **CRYPT-004**: Verify AES-GCM implementation (used in QUIC)
  - [ ] Tag length exactly 16 bytes required
  - [ ] Counter wrap-around at 2^32 blocks: nonce reuse detection
  - [ ] Associated data length overflow in GHASH

- [ ] **CRYPT-005**: Verify Merkle tree (bmtree) implementation soundness
  - [ ] `fd_bmtree.h`: single-node tree produces correct root
  - [ ] Odd-node tree: correct padding of last leaf
  - [ ] Proof verification: path with wrong side (left vs right) accepted

- [ ] **CRYPT-006**: Verify Reed-Solomon FEC encoding/decoding correctness
  - [ ] FEC set with maximum coding shreds: reconstruction correct
  - [ ] FEC set with exactly `data_shred_cnt` shreds (no erasures): verified without RS
  - [ ] Corrupted coding shred causes incorrect reconstruction accepted as valid

- [ ] **CRYPT-007**: Verify AVX-512 accelerated paths produce identical results to reference
  - [ ] ED25519 AVX-512 batch vs scalar: same result for same inputs
  - [ ] CPU without AVX-512: fallback correctly used (CPUID check)
  - [ ] SHA-256 AVX2 path vs scalar: identical output

---

## 24. RPC / HTTP Server

🟠 **MEDIUM**

**Files:** `src/discof/rpc/fd_rpc_tile.c`, `src/discof/rpc/fuzz_rpc.c`

> **Note:** #9168 covers H2 RST_STREAM buffer checks and untrusted bank index from replay tile.

- [ ] **RPC-001**: Verify HTTP request parsing handles malformed requests safely
  - [ ] Request with `Content-Length` > body: partial read leaves socket in bad state
  - [ ] Request with `Transfer-Encoding: chunked` and malformed chunk size
  - [ ] Request with very long URI or header values (>65KB)

- [ ] **RPC-002**: Verify JSON body parsing is bounded
  - [ ] JSON object with thousands of keys: O(n^2) parsing behavior
  - [ ] Deeply nested JSON (stack overflow in recursive parser)
  - [ ] JSON string with escape sequences exceeding output buffer

- [ ] **RPC-003**: Verify RPC response does not leak sensitive information
  - [ ] Error messages include internal state (addresses, pointers)
  - [ ] Timing side channel on `getBalance` for non-existent accounts

- [ ] **RPC-004**: Verify concurrent RPC requests cannot corrupt shared state
  - [ ] Multiple simultaneous `sendTransaction` requests: duplicate processing
  - [ ] `getBlock` during active block replay: stale or partial block returned

- [ ] **RPC-005**: Verify tarball-serving endpoint (if any) is path-traversal-safe
  - [ ] `fuzz_rpc_tarball.c` suggests tarball handling: archive path escapes expected root
  - [ ] Large tarball causes OOM in RPC tile

---

## 25. Forest (Fork Tree)

🔴 **HIGH**

**Files:** `src/discof/forest/fd_forest.c`, `src/discof/forest/fd_forest.h`

> **Note:** #9166 covers forest cycles and repair flow assertions.

- [ ] **FOREST-001**: Verify forest pool exhaustion handling
  - [ ] Pool capacity reached: new FEC set rejected silently or with crash
  - [ ] Orphaned subtrees consuming pool indefinitely when parent never arrives

- [ ] **FOREST-002**: Verify BFS traversal in forest is bounded
  - [ ] Deque capacity for BFS traversal bounded by `ele_max`
  - [ ] Circular ancestry (not a tree): BFS loops indefinitely

- [ ] **FOREST-003**: Verify frontier and subtrees hash maps handle hash collisions
  - [ ] Adversarial slot numbers that hash to the same bucket
  - [ ] Chain length unbounded → O(n) lookup under targeted attack

- [ ] **FOREST-004**: Verify consumed/requests tracking prevents duplicate processing
  - [ ] Same FEC set delivered twice: processed once
  - [ ] Consumed set evicted before corresponding replay completes

- [ ] **FOREST-005**: Verify forest version counter is not susceptible to race condition
  - [ ] `ver_inc` cleanup via `__attribute__((cleanup))`: version incremented even on error path
  - [ ] Consumer sees intermediate version during structural update

---

## Appendix: Priority Reference

| Priority | Severity | Focus |
|----------|----------|-------|
| 🟣 CRITICAL | RCE, key compromise, fund loss, invalid sig acceptance | VM, CPI, runtime conformance, ELF, replay |
| 🔴 HIGH | Bank hash mismatch, sandbox escape, accounts DB corruption, consensus failure | Network, shred, consensus, snapshot, funk |
| 🟠 MEDIUM | Leader crash, invalid block, liveness failure | Repair, IPC, RPC |
| 🟡 LOW | Limited liveness, configuration-dependent issues | Minor edge cases |

## Appendix: Key File Reference

| Component | Primary Files |
|-----------|---------------|
| QUIC | `src/waltz/quic/fd_quic.c`, `fd_quic_conn.c`, `fd_quic_retry.h` |
| sBPF VM | `src/flamenco/vm/fd_vm_interp_core.c`, `fd_vm_private.h` |
| CPI | `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c` |
| ELF Loader | `src/ballet/sbpf/fd_sbpf_loader.c` |
| System Programs | `src/flamenco/runtime/program/` |
| Replay | `src/discof/replay/fd_replay_tile.c` |
| PoH | `src/discof/poh/fd_poh.c` |
| Gossip | `src/flamenco/gossip/fd_gossip.c`, `src/discof/gossip/fd_gossip_tile.c` |
| Shred | `src/disco/shred/fd_shred_tile.c`, `fd_fec_resolver.c` |
| Reasm | `src/discof/reasm/fd_reasm.c` |
| Tower/Ghost | `src/choreo/tower/`, `src/choreo/ghost/` |
| Equivocation | `src/choreo/eqvoc/fd_eqvoc.c` |
| Forest | `src/discof/forest/fd_forest.c` |
| Repair | `src/discof/repair/fd_repair.c` |
| Funk | `src/funk/fd_funk.c`, `fd_funk_rec.c` |
| Snapshot | `src/discof/restore/utils/` |
| Sandbox | `src/util/sandbox/fd_sandbox.c` |
| Cryptography | `src/ballet/ed25519/`, `src/ballet/sha256/`, `src/ballet/aes/` |
| RPC | `src/discof/rpc/fd_rpc_tile.c` |
