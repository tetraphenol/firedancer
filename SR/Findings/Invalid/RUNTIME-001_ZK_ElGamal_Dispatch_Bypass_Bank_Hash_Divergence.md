# RUNTIME-001: ZK ElGamal Program Dispatch Table Feature Gate Bypass

## Severity
INVALID (Error code divergence does not affect bank hash)

## Summary
Firedancer's native program dispatch table hardcodes the ZK ElGamal proof program as always-active (`feature_enable_offset = ULONG_MAX`), bypassing the `zk_elgamal_proof_program_enabled` feature gate. The differential fuzzer produces confirmed mismatches (FD returns `InvalidInstructionData` while Agave returns `UnsupportedProgramId`) when the feature set is artificially constrained. However, this divergence cannot cause a bank hash mismatch under any conditions because transaction error codes are not included in the bank hash computation.

## Why This Is Invalid

**Error codes are not consensus-relevant.** The bank hash is:
```
SHA256(SHA256(prev_bank_hash || signature_count || last_blockhash) || lthash)
```
Where `lthash` is the cumulative lattice hash of modified accounts: `blake3(lamports || data || executable || owner || pubkey)`. Transaction error codes are stored in-memory in `fd_txn_out_t.err` only and never written to any account data or hashed structure.

**The commit path is error-code-agnostic.** In `fd_runtime.c:1193`, the commit checks `if( txn_out->err.txn_err )` - a truthiness check, not a value check. Both `InvalidInstructionData` (-3) and `UnsupportedProgramId` (-31) trigger the identical "fees only" path.

**Fee deduction is execution-independent.** The fee is computed and deducted in `fd_executor_create_rollback_fee_payer_account()` (fd_executor.c:766) before execution begins. The rollback fee payer - with fees already deducted - is what gets committed on failure. The fee amount derives from the transaction structure (ComputeBudget instructions, signature count), not the execution result.

**Under mainnet conditions, the error codes are identical anyway.** With `zk_elgamal_proof_program_enabled`=active, `disable`=active (cleaned up), `reenable`=inactive: both FD and Agave dispatch to the handler, both check the disable/reenable gates, and both return `InvalidInstructionData`.

## Vulnerability Details (Retained for Reference)

**Location:** `src/flamenco/runtime/fd_executor.c:69` (dispatch table entry)

**Code defect:** The MAP_PERFECT_3 entry uses `feature_enable_offset = ULONG_MAX` instead of `offsetof(fd_features_t, zk_elgamal_proof_program_enabled)`. This contradicts `fd_builtin_programs.c:64` which uses the correct offset for builtin registration. The dispatch table takes precedence via `fd_executor_program_is_active()` (lines 85-92).

**Feature gate chain:**
- `zk_elgamal_proof_program_enabled` - original gate. Active on mainnet.
- `disable_zk_elgamal_proof_program` - disables handler. Cleaned up (always active).
- `reenable_zk_elgamal_proof_program` - re-enables after disable. Not active on mainnet.

**FD handler check** (fd_zk_elgamal_proof_program.c:314): `!reenable` - simplified, omits `disable` check.
**Agave handler check** (lib.rs:175-187): `disable && !reenable` - full check.
These are logically equivalent because `disable` is cleaned up (always true).

## Fuzzer vs Consensus

The differential fuzzer (fuzz_instr_exec_diff, fuzz_txn_exec_diff) correctly identifies an error code mismatch when features are artificially constrained. This is a real code-level divergence - FD dispatches when it shouldn't. But error code divergences are a different class from account state divergences: only the latter affect the bank hash and consensus.
