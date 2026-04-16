# VOTE-001: Vote State Deserializer Accepts Unbounded prior_voters.idx

## Severity
LOW

## Summary
The hand-written vote state bincode deserializer (`fd_vote_codec.c`) does not validate that `prior_voters.idx` is within the bounds of the circular buffer (max 32). While the runtime code guards against OOB access, this creates a behavioral divergence with Agave: Agave's Rust code would panic on `buf[idx]` when `idx >= 32`, failing the transaction, while Firedancer would silently use epoch 0 and wrap the index.

## Vulnerability Details

**Location:** `src/flamenco/runtime/program/vote/fd_vote_codec.c:259`

**Root Cause:**
`deser_prior_voters()` reads `prior_voters->idx` as a raw `u64` from wire data without bounds checking:
```c
READ_U64( prior_voters->idx, ptr, rem );  // No validation that idx <= PRIOR_VOTERS_MAX (32)
```

**Attack Vector:**
1. Attacker crafts a vote account with `prior_voters.idx = 33` (or any value > 32) and `is_empty = false`
2. This requires either: (a) corrupted snapshot, or (b) a separate bug allowing arbitrary account data writes
3. A transaction calling `set_new_authorized_voter` on this account behaves differently:
   - Agave: Rust panics on `buf[33]` array index OOB, transaction fails
   - Firedancer: guarded by `prior_voters->idx < 32` check at fd_vote_state_v3.c:167, uses epoch 0 instead, transaction succeeds

**Prerequisites:**
- Vote account must contain corrupted data with `prior_voters.idx > 32`
- On mainnet, the vote program always wraps `idx %= 32` (fd_vote_state_v3.c:177), so this value cannot be > 31 under normal execution
- Requires either snapshot corruption or a separate vulnerability to inject

## Impact

If the precondition is met, the divergence would cause different transaction outcomes between Firedancer and Agave: one succeeds (silently wraps idx), the other fails (Rust panic on OOB). This produces a bank hash mismatch, which is HIGH severity - but the precondition is extremely unlikely on mainnet.

**Discovered by:** Fuzzer `fuzz_vote_codec` with invariant checking, crash input `crash-efd10652306acd180932dcffc6ec9d028fa101eb`
