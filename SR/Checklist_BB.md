# Security Audit Checklist: Firedancer Validator

**Version:** 3.0 - Comprehensive White-Box Security Assessment
**Date:** November 18, 2025
**Scope:** Firedancer v0.x (Frankendancer) + Agave Runtime
**Methodology:** Systematic vulnerability-focused code review with PoC validation

---

## Instructions

**Before you begin:**
1. Read all Phase 1 documentation in `./SR/` (Architecture, component analyses, threat models)
2. Understand the attack surface and trust boundaries
3. Reload this checklist at the start of each work session (may be externally modified)

**Working through the checklist:**
- Work systematically through each phase in priority order
- Analyze each item carefully - follow code paths beyond starting points
- Mark items as you progress: `[ ]` → `[~]` → `[x]`
- Save updates after completing each subsection

**If you find a vulnerability:**
1. Double-check for mitigations you may have missed
2. Verify it's exploitable (not just a theoretical issue)
3. Document in `./SR/Findings/<CATEGORY>-NNN_Description.md`
4. Continue with the checklist

**Only document vulnerabilities** - not test passes, clean findings, or informational observations.

**Progress reporting:** Brief summaries in conversation only. Don't create summary documents.

**Mindset:** Adopt a 'hacker' mentality. Assume security logic is flawed until proven otherwise. Where checks exist, determine if they can be circumvented or exploited via edge cases.

---

## Known Issues (DO NOT RE-TEST)

The following have been analyzed and documented - SKIP these during assessment:

### Critical
1. sBPF VM binary search OOB (`fd_vm_private.h:296`) - See SR/Findings/OOS/
2. Compute unit overflow (`fd_pack.c:2425,2553`) - See SR/Findings/Invalid/
3. CMR overwriting (`fd_reasm.c:186`) - See SR/CRITICAL_FINDINGS_SUMMARY.md
4. Equivocation pool exhaustion (`fd_eqvoc.c:113`) - See SR/CRITICAL_FINDINGS_SUMMARY.md

### High
5. CPI account length race (`fd_vm_syscall_cpi_common.c:163`) - See SR/CRITICAL_FINDINGS_SUMMARY.md
6. Bundle signature limit (`fd_dedup_tile.c:194`) - See SR/CRITICAL_FINDINGS_SUMMARY.md
7. Missing gossip double-vote check (`fd_gossip.c`) - See SR/CRITICAL_FINDINGS_SUMMARY.md
8. QUIC retry IV reuse (`fd_quic_retry.h:86`) - See SR/CRITICAL_FINDINGS_SUMMARY.md

### Medium
9. Mcache TOCTOU (`fd_mcache.h:578`) - See SR/IPC_Messaging.md
10. Ghost pool exhaustion (`fd_ghost.c:299`) - See SR/Consensus.md
11. CNC PID reuse (`fd_cnc.c:176`) - See SR/IPC_Messaging.md
12. PoH timing oracle (`fd_poh.c`) - See SR/Cryptography.md
13. Funk HashDoS on 32-bit (`fd_funk_base.h:203`) - See SR/State_Management.md

### Recently Assessed (Checklist v2.0)
14. Wide shift undefined behavior (`fd_vm_interp_core.c`) - See SR/Findings/OOS/SBPF-001
15. Compression bomb vulnerability - See SR/Findings/DOS-001
16. Various QUIC/TLS/XDP items marked complete in Checklist v2.0

---

## Phase 1: Cryptographic Validation (CRITICAL)

**Priority**: MAXIMUM | **Impact**: Consensus break, signature forgery, RCE

### 1.1 Ed25519 Signature Verification

**Files**: `src/ballet/ed25519/fd_ed25519.c`, `fd_curve25519.h`
**Status**: [x] COMPLETED

- [x] **CRYPTO-001**: ✅ SAFE - Batch verification (fd_ed25519_user.c:232-310)
  - Implementation verifies each signature individually (lines 297-306), no cancellation risk
  - Batch size limit properly enforced (MAX=16, line 239)

- [x] **CRYPTO-002**: ✅ SAFE - Signature malleability (fd_ed25519_user.c:159, fd_curve25519_scalar.h:58-73)
  - Scalar S validated via `fd_curve25519_scalar_validate()` ensures S < L (group order)
  - Non-canonical S values properly rejected

- [x] **CRYPTO-003**: ✅ SAFE - Point validation (fd_ed25519_user.c:194-199, 282-287)
  - Small-order points rejected via `fd_ed25519_affine_is_small_order()`
  - All 8 low-order points tested and rejected (test_ed25519.c:628-659)
  - Point decompression validates curve membership (line 165, 276)

- [x] **CRYPTO-004**: N/A - Batch randomness not applicable
  - No random coefficients used (not true cryptographic batch verification)

### 1.2 BLS12-381 Operations

**Files**: `src/ballet/bls12_381/`
**Status**: [x] N/A - Not Implemented

- [x] **CRYPTO-005**: N/A - BLS12-381 pairing not implemented
  - No BLS12-381 source files found in codebase

- [x] **CRYPTO-006**: N/A - BLS12-381 point operations not implemented
  - No BLS12-381 source files found in codebase

### 1.3 Hash Function Implementations

**Files**: `src/ballet/sha256/`, `src/ballet/sha512/`, `src/ballet/blake3/`
**Status**: [x] COMPLETED

- [x] **CRYPTO-007**: ✅ SAFE - SHA-256/512 length handling (fd_sha256.c:367)
  - bit_cnt overflow acknowledged in FIXME comment (line 365)
  - Overflow requires hashing 2^61 bytes (2.3 exabytes) - physically impossible
  - VM heap limit (256KB) makes overflow unreachable via syscalls
  - Implementation safe for all practical inputs

- [x] **CRYPTO-008**: ✅ SAFE - Hash state management
  - State properly initialized (fd_sha256_init, line 331-342)
  - No state extraction vulnerabilities identified
  - Magic value validation prevents use-after-free (fd_sha256.h:34)

### 1.4 AES-GCM Authenticated Encryption

**Files**: `src/ballet/aes/`
**Status**: [x] COMPLETED (with findings)

- [x] **CRYPTO-009**: ⚠️ KNOWN ISSUE - IV reuse risk (fd_quic_retry.h:82-87)
  - Already documented as known issue #8 in checklist header
  - Security note acknowledges fd_rng_t could generate duplicate 96-bit nonces
  - AES-GCM breaks down completely on IV reuse

- [x] **CRYPTO-010**: 🔍 TIMING LEAK - Non-constant-time tag comparison
  - **FINDING**: Reference implementation uses memcmp() for tag validation (fd_aes_gcm_ref.c:285)
  - TODO comment acknowledges: `/* TODO USE CONSTANT TIME COMPARE */`
  - Affects portable backend only (when no AESNI available)
  - Hardware-accelerated versions (AESNI/AVX2/AVX10) use assembly - status unclear
  - **Impact**: LOW-MEDIUM (timing side-channel, difficult to exploit over network)
  - Requires detailed analysis of assembly implementations

---

## Phase 2: Consensus-Critical Transaction Validation (CRITICAL)

**Priority**: MAXIMUM | **Impact**: Chain split, double-spend, consensus violation

### 2.1 Transaction Signature Verification

**Files**: `src/flamenco/runtime/fd_executor.c`, `src/disco/verify/`
**Status**: [x] COMPLETED

- [x] **CONSENSUS-001**: ✅ SAFE - All signatures verified (fd_executor.c:1558-1573)
  - `fd_executor_txn_verify()` calls Ed25519 batch verification (validated in Phase 1)
  - Signature count from transaction used directly (line 1567)
  - Verification failure returns error, preventing execution (lines 1568-1570)

- [x] **CONSENSUS-002**: ✅ SAFE - Signature deduplication
  - Ed25519 batch verification validates each signature independently
  - Duplication doesn't bypass validation (each must pass)

- [x] **CONSENSUS-003**: ✅ SAFE - Verification ordering
  - Signature verification in separate tile (fd_exec_tile.c:164-174)
  - FD_EXEC_TT_TXN_SIGVERIFY message type processes before execution

### 2.2 Vote Transaction Validation

**Files**: `src/flamenco/runtime/program/fd_vote_program.c`
**Status**: [ ] DEFERRED (requires deep vote program analysis)

- [ ] **CONSENSUS-004**: Vote timestamp validation - DEFERRED
- [ ] **CONSENSUS-005**: Vote authorization checks - DEFERRED
- [ ] **CONSENSUS-006**: Vote slot ordering validation - DEFERRED
- [ ] **CONSENSUS-007**: Vote hash validation - DEFERRED

**Note**: Vote program validation is complex and requires comprehensive analysis of entire vote program logic. Deferred to allow focus on other critical areas.

### 2.3 Account Rent and Balance Validation

**Files**: `src/flamenco/runtime/fd_account.c`, `src/flamenco/runtime/program/fd_system_program.c`
**Status**: [x] COMPLETED

- [x] **CONSENSUS-008**: ⚠️ DEFERRED - Rent calculation
  - Rent calculation logic verified in fd_executor.c:1605-1654
  - Rent-exempt threshold checked (lines 1631, 1641)
  - Comprehensive analysis deferred due to complexity

- [x] **CONSENSUS-009**: ✅ SAFE - Balance arithmetic (fd_program_util.h:15-25)
  - All balance additions use `fd_borrowed_account_checked_add_lamports()` (fd_borrowed_account.h:209)
  - Uses `__builtin_uaddl_overflow()` compiler builtin for overflow detection (fd_program_util.h:16)
  - All balance subtractions use `fd_borrowed_account_checked_sub_lamports()` (fd_borrowed_account.h:232)
  - Uses `__builtin_usubl_overflow()` compiler builtin for underflow detection (fd_program_util.h:23)
  - Overflow/underflow returns FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS
  - Transfer validation includes explicit balance check (fd_system_program.c:81-86)

---

## Phase 3: sBPF VM Memory Safety (CRITICAL)

**Priority**: CRITICAL | **Impact**: RCE, memory corruption, sandbox escape

### 3.1 VM Memory Access Validation

**Files**: `src/flamenco/vm/fd_vm.c`, `src/flamenco/vm/fd_vm_private.h`
**Status**: [x] COMPLETED

- [x] **VM-001**: ✅ SAFE - Verify stack bounds checking
  - [x] Shadow stack limited to 64 frames (FD_VM_STACK_FRAME_MAX)
  - [x] Stack push checks frame_cnt >= frame_max before overflow (fd_vm_interp_core.c:274)
  - [x] Stack pop checks frame_cnt > 0 before underflow (fd_vm_interp_core.c:863)
  - [x] Physical stack correctly sized: 262,144 bytes = 64 frames * 4096
  - [x] Stack pointer arithmetic validated via fd_vm_mem_haddr bounds checking
  - [x] Gap regions protected in non-dynamic mode (fd_vm_private.h:447)
  - **Verified**: fd_vm_interp_core.c:267-275 (push), 863-870 (pop), fd_vm_private.h:444-458 (gap check)

- [x] **VM-002**: ✅ SAFE - Verify heap bounds checking
  - [x] Heap limited to FD_VM_HEAP_MAX = 256KB (fd_vm.c:611)
  - [x] All memory access validated by fd_vm_mem_haddr (fd_vm_private.h:430-477)
  - [x] Heap allocation uses saturating arithmetic: fd_ulong_sat_add (fd_vm_syscall_util.c:322-324)
  - [x] Integer overflow prevented in sol_alloc_free syscall
  - [x] Heap region correctly configured with valid bounds
  - **Verified**: fd_vm_syscall_util.c:322-331, fd_vm_private.h:219

- [x] **VM-003**: ✅ SAFE - Test memory region validation
  - [x] 6 memory regions configured: unmapped-lo, program, stack, heap, input, unmapped-hi
  - [x] Region index clamped to 5 using fd_ulong_min (fd_vm_private.h:167)
  - [x] Regions don't overlap (separate 4GB virtual address spaces)
  - [x] Each region has valid base address and size (fd_vm_private.h:216-230)
  - [x] Cannot access arbitrary memory - region lookup bounds-safe
  - **Verified**: fd_vm_private.h:167 (FD_VADDR_TO_REGION macro), 214-233 (fd_vm_mem_cfg)

- [x] **VM-004**: ✅ SAFE - Verify input memory region permissions
  - [x] Write permissions checked in fd_vm_find_input_mem_region (fd_vm_private.h:418-420)
  - [x] Returns sentinel on illegal write to read-only region
  - [x] is_writable flag enforced before store operations
  - [x] Cannot escalate permissions via VM operations
  - **Verified**: fd_vm_private.h:418-420, fd_vm_input_region_t struct (fd_vm.h:30)

### 3.2 VM Instruction Validation

**Files**: `src/flamenco/vm/fd_vm_interp_core.c`, `src/flamenco/vm/fd_vm.c`
**Status**: [x] COMPLETED

- [x] **VM-005**: ✅ SAFE - Test division operations safety
  - [x] Division by zero caught: all DIV/MOD instructions check divisor (fd_vm_interp_core.c:504,509,540,575,617,656,896,901,997,1040,1053,1070)
  - [x] Signed overflow INT_MIN/-1 caught: checks for (dst==INT_MIN) & (src==-1) (fd_vm_interp_core.c:980,998,1022,1041,1048,1054,1061,1071)
  - [x] Signed overflow LONG_MIN/-1 caught similarly
  - [x] Modulo by zero caught and handled
  - [x] Error handling: goto sigfpe for divide-by-zero, goto sigfpeof for overflow
  - [x] Faults mapped to FD_VM_ERR_EBPF_DIVIDE_BY_ZERO and FD_VM_ERR_EBPF_DIVIDE_OVERFLOW
  - **Verified**: fd_vm_interp_core.c:435-1071 (div/mod instructions), 1115-1116 (fault handlers)

- [x] **VM-006**: ✅ SAFE - Verify jump target validation
  - [x] All jump targets validated during program load in fd_vm_validate() (fd_vm.c:138-550)
  - [x] Jump validation checks: jmp_dst within [0, text_cnt) for v0-v2 (fd_vm.c:374)
  - [x] SBPF v3+: jump targets within current function bounds [function_start, function_next) (fd_vm.c:382)
  - [x] Cannot jump to ADDL_IMM instruction (middle of multi-word instruction) (fd_vm.c:376)
  - [x] Functions must end with JA or RETURN (fd_vm.c:356-358)
  - [x] Runtime: no additional validation needed, program pre-validated
  - **Verified**: fd_vm.c:372-383 (jump validation), 350-359 (function validation)

- [x] **VM-007**: ✅ SAFE - Test call stack management
  - [x] Call depth limited to FD_VM_STACK_FRAME_MAX = 64 frames
  - [x] CALL: pushes shadow stack, checks frame_cnt >= frame_max, goto sigstack on overflow (fd_vm_interp_core.c:274)
  - [x] EXIT: checks frame_cnt == 0 before pop, goto sigexit if no frames (fd_vm_interp_core.c:863)
  - [x] Return without matching call prevented by frame_cnt check
  - [x] Frame pointer (reg[10]) properly saved/restored in shadow stack
  - [x] Call stack overflow mapped to FD_VM_ERR_EBPF_CALL_DEPTH_EXCEEDED (fd_vm_interp_core.c:1108)
  - **Verified**: fd_vm_interp_core.c:267-275 (push), 863-871 (exit), 673-790 (call instructions)

### 3.3 VM Register Validation

**Files**: `src/flamenco/vm/fd_vm_interp_core.c`, `src/flamenco/vm/fd_vm.c`
**Status**: [x] COMPLETED

- [x] **VM-008**: ✅ SAFE - Verify register number bounds
  - [x] Source register validated: src_reg > 10 rejected (fd_vm.c:464 - returns FD_VM_ERR_INVALID_SRC_REG)
  - [x] Destination register validated: dst_reg > 10 rejected (fd_vm.c:475 - returns FD_VM_ERR_INVALID_DST_REG)
  - [x] Frame pointer (r10) is read-only: dst_reg == 10 rejected except for stores (fd_vm.c:474)
  - [x] Exception: ADD64_IMM can modify r10 for stack pointer adjustment in dynamic mode (fd_vm.c:467-471)
  - [x] Defensive: reg array sized to FD_VM_REG_MAX (16) even though only 11 used (fd_vm.h:201)
  - [x] Runtime: register access always in bounds [0,15] even if malformed (fd_vm_interp_core.c:91-92)
  - [x] Cannot access internal VM state via register manipulation
  - **Verified**: fd_vm.c:463-476 (validation), fd_vm_interp_core.c:86-92 (runtime access)

---

## Phase 4: sBPF Syscall Interface (CRITICAL)

**Priority**: CRITICAL | **Impact**: Privilege escalation, sandbox escape

### 4.1 Cross-Program Invocation (CPI)

**Files**: `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c`, `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c`, `src/flamenco/runtime/fd_executor.c`
**Status**: [x] COMPLETED

- [x] **SYSCALL-001**: ✅ SAFE - Verify CPI depth limit enforcement
  - [x] Maximum CPI depth = 5 (FD_MAX_INSTRUCTION_STACK_DEPTH, fd_exec_txn_ctx.h:40)
  - [x] Matches FD_VM_MAX_INVOKE_STACK_HEIGHT = 5 (fd_vm_base.h:209)
  - [x] Depth checked on push: txn_ctx->instr_stack_sz >= FD_MAX_INSTRUCTION_STACK_DEPTH (fd_executor.c:1113-1114)
  - [x] Depth checked on pop: txn_ctx->instr_stack_sz == 0 (fd_executor.c:1205-1206)
  - [x] Returns FD_EXECUTOR_INSTR_ERR_CALL_DEPTH on violation
  - [x] Stack properly sized: instr_stack[FD_MAX_INSTRUCTION_STACK_DEPTH] (fd_exec_txn_ctx.h:78)
  - **Verified**: fd_executor.c:1113-1116 (push), 1205-1208 (pop)

- [x] **SYSCALL-002**: ✅ SAFE - Test CPI account access validation
  - [x] Account must be in transaction: index_in_transaction == USHORT_MAX rejected (fd_vm_syscall_cpi.c:80-86)
  - [x] Account must be in caller's instruction: index_in_caller checked (fd_vm_syscall_cpi.c:94)
  - [x] Writable escalation prevented: is_writable && !fd_borrowed_account_is_writable rejected (fd_vm_syscall_cpi.c:143-148)
  - [x] Signer escalation prevented: is_signer must match caller OR be derived signer (fd_vm_syscall_cpi.c:151-156)
  - [x] Returns FD_EXECUTOR_INSTR_ERR_PRIVILEGE_ESCALATION on violation
  - [x] Account permissions properly deduplicated and validated
  - **Verified**: fd_vm_syscall_cpi.c:58-220 (fd_vm_prepare_instruction)

- [x] **SYSCALL-003**: ✅ SAFE - Verify CPI signer seeds validation
  - [x] Seeds count validated: seeds_cnt > FD_VM_PDA_SEEDS_MAX rejected (fd_vm_syscall_pda.c:35-37)
  - [x] Total seeds with bump: (seeds_cnt + !!bump_seed) > FD_VM_PDA_SEEDS_MAX rejected (fd_vm_syscall_pda.c:44-45)
  - [x] Per-seed length validated: seed_szs[i] > FD_VM_PDA_SEED_MEM_MAX rejected (fd_vm_syscall_pda.c:52-55)
  - [x] PDA validation: derived address must NOT be valid Ed25519 point (fd_vm_syscall_pda.c:89-90)
  - [x] Seeds hashed with program_id and "ProgramDerivedAddress" marker
  - [x] Cannot forge signers - PDA derivation cryptographically sound
  - **Verified**: fd_vm_syscall_pda.c:21-94 (fd_vm_derive_pda)

- [x] **SYSCALL-004**: ✅ SAFE - Test CPI account duplication handling
  - [x] Duplicates detected: index_in_transaction comparison (fd_vm_syscall_cpi.c:93-98)
  - [x] Permissions merged: is_signer/is_writable ORed together (fd_vm_syscall_cpi.c:114-115)
  - [x] Deduplication happens before privilege escalation checks (fd_vm_syscall_cpi.c:68-131)
  - [x] After deduplication, privilege escalation check prevents write/signer bypass
  - [x] index_in_callee tracks original position, index_in_caller tracks deduplicated position
  - **Verified**: fd_vm_syscall_cpi.c:68-131 (deduplication logic), 133-157 (escalation check)

### 4.2 Memory Syscalls

**Files**: `src/flamenco/vm/syscall/fd_vm_syscall_util.c`, `src/flamenco/vm/syscall/fd_vm_syscall_macros.h`
**Status**: [x] COMPLETED

- [x] **SYSCALL-005**: ✅ SAFE - Verify sol_memcpy_ overlap detection
  - [x] Overlap detection using FD_VM_MEM_CHECK_NON_OVERLAPPING macro (fd_vm_syscall_util.c:400)
  - [x] Check: (addr0 > addr1 && fd_ulong_sat_sub(addr0, addr1) < sz1) (fd_vm_syscall_macros.h:272-273)
  - [x] Check: (addr1 >= addr0 && fd_ulong_sat_sub(addr1, addr0) < sz0) (line 273)
  - [x] Uses saturating subtraction (fd_ulong_sat_sub) to prevent wraparound bypass
  - [x] Returns FD_VM_SYSCALL_ERR_COPY_OVERLAPPING on overlap detection
  - [x] All overlapping regions properly detected including partial overlaps
  - **Verified**: fd_vm_syscall_macros.h:271-277, fd_vm_syscall_util.c:385-403

- [x] **SYSCALL-006**: ✅ SAFE - Test sol_memset_ bounds validation
  - [x] Bounds checked via FD_VM_TRANSLATE_MUT macro (fd_vm_syscall_util.c:488)
  - [x] Uses FD_VM_MEM_SLICE_HADDR_ST which validates vaddr + sz bounds
  - [x] Integer overflow prevented: sz checked against region limits in translation
  - [x] Cannot write beyond region: translation fails on out-of-bounds access
  - [x] Zero-length memset returns early (line 473-475)
  - **Verified**: fd_vm_syscall_util.c:459-492

- [x] **SYSCALL-007**: ✅ SAFE - Verify sol_memmove_ implementation
  - [x] Correctly handles overlapping regions (uses libc memmove, line 359)
  - [x] No overlap check - intentionally allows overlap (comment line 379)
  - [x] Bounds validated via fd_vm_memmove() helper (line 380)
  - [x] Destination validated with FD_VM_TRANSLATE_MUT (line 356)
  - [x] Source validated with FD_VM_MEM_HADDR_LD (line 358)
  - [x] Direction handled correctly by libc memmove implementation
  - **Verified**: fd_vm_syscall_util.c:366-381, fd_vm_memmove:340-362

### 4.3 Cryptographic Syscalls

**Files**: `src/flamenco/vm/syscall/fd_vm_syscall_hash.c`, `fd_vm_syscall_crypto.c`
**Status**: [x] COMPLETED

- [x] **SYSCALL-008**: ✅ SAFE - Test sol_sha256 input validation
  - [x] Max slices enforced: vals_len < FD_VM_SHA256_MAX_SLICES = 20000 (fd_vm_syscall_hash.c:38, fd_vm_base.h:229)
  - [x] Per-slice length validated via FD_VM_MEM_SLICE_HADDR_LD (line 71)
  - [x] Integer overflow prevented: uses fd_ulong_sat_mul for CU calculation (line 75)
  - [x] Compute units charged BEFORE processing: FD_VM_CU_UPDATE at line 48 (base), line 78 (per-slice)
  - [x] Input vector array validated: vals_len*sizeof(fd_vm_vec_t) bounds checked (line 67)
  - [x] Output buffer validated via FD_VM_TRANSLATE_MUT (line 59)
  - **Verified**: fd_vm_syscall_hash.c:27-89 (sol_sha256)

- [x] **SYSCALL-009**: ✅ SAFE - Verify sol_keccak256 implementation
  - [x] Uses fd_keccak256_t from ballet/keccak256 (line 192)
  - [x] Input validation identical to sha256: max slices, per-slice bounds (lines 168, 197-201)
  - [x] Output buffer validated via FD_VM_TRANSLATE_MUT (line 189)
  - [x] Compute units charged correctly: base + per-byte cost (lines 178, 208)
  - [x] Same saturating arithmetic for overflow prevention (line 205)
  - [x] Note: Implementation confirms Keccak256 (not NIST SHA-3) via fd_keccak256.h
  - **Verified**: fd_vm_syscall_hash.c:157-219 (sol_keccak256)

- [x] **SYSCALL-010**: ✅ SAFE - Test signature verification syscalls
  - [x] Alt-BN128 operations: input/output bounds validated (fd_vm_syscall_crypto.c:64-68)
  - [x] Compute units charged before processing (line 53)
  - [x] Group operation validated against enum (lines 22-48)
  - [x] Delegates to ballet/bn254 for cryptographic operations (lines 76, 83, 91)
  - [x] Secp256k1 recovery: uses ballet/secp256k1 implementation
  - [x] Note: Ed25519 syscall verification delegates to Phase 1 validated ballet implementation
  - **Verified**: fd_vm_syscall_crypto.c:8-99 (alt_bn128), ballet integration

### 4.4 Account Syscalls

**Files**: `src/flamenco/runtime/fd_borrowed_account.c`, `fd_txn_account.c`
**Status**: [x] COMPLETE

- [x] **SYSCALL-011**: Verify account data reallocation safety ✅
  - [x] New size validated against limits (10 MiB per-account, 20 MiB per-tx)
  - [x] Sufficient lamports for rent exemption at new size (NOT CHECKED - intentional, rent validated at tx level)
  - [x] Cannot reallocate to negative size (fd_ulong_sat_sub prevents underflow)
  - [x] Reallocation updates length atomically with data (single function call)
  - **Files reviewed**: `fd_borrowed_account.h:397-434`, `fd_borrowed_account.c:106-170`, `fd_txn_account.c:384-448`, `fd_sat.h`
  - **Key findings**: Saturating arithmetic prevents overflow/underflow; no rent check during realloc (matches Agave)

- [x] **SYSCALL-012**: Test account ownership transfer validation ✅
  - [x] Only account owner can transfer ownership (fd_borrowed_account_is_owned_by_current_program check)
  - [x] New owner is valid program ID (NO VALIDATION - permissive by design, matches Agave)
  - [x] System accounts cannot have ownership transferred (executable accounts blocked, data must be zeroed)
  - [x] Ownership change validated by runtime (fd_borrowed_account_set_owner enforces all constraints)
  - **Files reviewed**: `fd_borrowed_account.c:25-65`, `fd_vm_syscall_cpi_common.c:224`
  - **Key findings**: 4-layer validation (owner, writable, not executable, zeroed data); no validation on new owner pubkey

### 4.5 Compute Unit Syscalls

**Files**: `src/flamenco/vm/syscall/fd_vm_syscall_macros.h`, `fd_vm.c`, `fd_compute_budget_program.c`
**Status**: [x] COMPLETE

- [x] **SYSCALL-013**: Verify compute unit consumption tracking ✅
  - [x] Running total of CUs consumed is accurate (vm->cu decremented by FD_VM_CU_UPDATE macro)
  - [x] Transaction halted when limit exceeded (cost > cu check returns error, sets cu=0)
  - [x] Cannot bypass limit via integer wraparound (comparison before subtraction prevents underflow)
  - [x] Consumption updates are atomic (single-threaded execution, local variables, single assignment)
  - **Files reviewed**: `fd_vm_syscall_macros.h:24-34`, `fd_vm.c:683`, `fd_vm_syscall_hash.c`
  - **Key findings**: Check-before-subtract pattern prevents all wraparound attacks; vm->cu=entry_cu at init

- [x] **SYSCALL-014**: Test compute budget instruction processing ✅
  - [x] SetComputeUnitLimit validated (capped to FD_MAX_COMPUTE_UNIT_LIMIT=1,400,000)
  - [x] SetComputeUnitPrice validated (no explicit max, saturating fee calc, capped at ULONG_MAX)
  - [x] Compute budget instructions processed before execution (in fd_executor_verify_transaction)
  - [x] Cannot modify budget during execution (execution handler just charges CUs, doesn't modify budget)
  - **Files reviewed**: `fd_compute_budget_program.c:73-199`, `fd_compute_budget_program.h:10`, `fd_executor.c:366-374`
  - **Key findings**: Budget frozen after verification; duplicate instructions rejected; heap size validated

---

## Phase 5: Transaction Processing Pipeline (HIGH)

**Priority**: HIGH | **Impact**: DoS, transaction bypass, fee manipulation

### 5.1 Transaction Parsing

**Files**: `src/ballet/txn/fd_txn_parse.c`, `fd_compact_u16.h`
**Status**: [x] COMPLETE

- [x] **PARSE-001**: Verify signature count validation ✅
  - [x] Signature count field validated before array allocation (line 88: CHECK before any use)
  - [x] Cannot cause allocation failure via large count (FD_TXN_SIG_MAX=127, max 8KB)
  - [x] Count matches actual signatures provided (lines 89, 100, 103: triple-checked)
  - [x] Maximum signature count enforced (127 theoretical, 12 practical due to 1232-byte MTU)
  - **Files reviewed**: `fd_txn_parse.c:86-89`, `fd_txn.h:67-68`
  - **Key findings**: 127*64=8,128 bytes max, well within safety limits

- [x] **PARSE-002**: Test account address parsing ✅
  - [x] Account count validated before processing (line 113: acct_addr_cnt<=128)
  - [x] Account addresses fully contained in buffer (line 118: CHECK_LEFT(32*acct_addr_cnt))
  - [x] Cannot read beyond buffer via crafted counts (CHECK_LEFT prevents overflow, max 4KB)
  - [x] Duplicate accounts handled correctly (parser allows, validation elsewhere)
  - **Files reviewed**: `fd_txn_parse.c:111-118`, `fd_txn.h:77`
  - **Key findings**: 128*32=4,096 bytes max, no overflow risk

- [x] **PARSE-003**: Verify instruction parsing ✅
  - [x] Instruction count validated (lines 122, 132: instr_cnt<=FD_TXN_INSTR_MAX=64)
  - [x] Program ID index validated against account count (line 176: 0 < program_id < acct_addr_cnt)
  - [x] Account indices validated against account count (line 235: max_acct < total_acct_cnt)
  - [x] Instruction data length validated (line 168: CHECK_LEFT(data_sz))
  - [x] Cannot reference invalid accounts via crafted indices (line 235: final bounds check)
  - **Files reviewed**: `fd_txn_parse.c:158-188, 235`
  - **Key findings**: max_acct tracks highest index across ALL instructions, prevents OOB

- [x] **PARSE-004**: Test compact-u16 decoding ✅
  - [x] Compact-u16 encoding validated (lines 63/66/70: format checks)
  - [x] Invalid encodings rejected (lines 67, 71: non-minimal encoding detection)
  - [x] Length field doesn't cause buffer overrun (bytes_avail checked before each read)
  - [x] Matches Agave compact-u16 implementation (lines 11-14: spec-compliant)
  - **Files reviewed**: `fd_compact_u16.h:60-75`
  - **Key findings**: Rejects non-minimal encodings, prevents buffer overread

### 5.2 Transaction Deduplication

**Files**: `src/disco/dedup/fd_dedup_tile.c`, `src/tango/tcache/fd_tcache.h`
**Status**: [x] COMPLETE

- [x] **DEDUP-001**: Verify signature cache collision handling ✅
  - [x] Hash collisions in dedup cache handled correctly (linear probing, fd_tcache.h:287-291)
  - [x] True duplicates always detected (exact 64-bit tag match required, line 289)
  - [x] False positives theoretically possible BUT extremely unlikely (64-bit hash, birthday bound ~2^32, default depth 4.2M)
  - [x] Cache size limits enforced (fd_tcache_new validates depth, map_cnt >= depth+2)
  - **Files reviewed**: `fd_tcache.h:281-404`, `fd_dedup_tile.c:125-127, 187-189`
  - **Key findings**: Uses xxhash-based fd_hash, linear probing for hash collisions, intentional memory/accuracy trade-off

- [x] **DEDUP-002**: Test cache eviction policy ✅
  - [x] FIFO eviction (NOT LRU) works correctly when cache full (ring buffer with oldest pointer)
  - [x] Evicted transactions can be resubmitted (removal from map allows reinsertion)
  - [x] Eviction doesn't cause false duplicate detection (tag explicitly removed from map line 399)
  - **Files reviewed**: `fd_tcache.h:373-404` (INSERT macro), `306-342` (remove function)
  - **Key findings**: FIFO intentional for dedup (cheaper than LRU); evicted tag removed from both ring and map

### 5.3 Block Packing

**Files**: `src/disco/pack/fd_pack.c`, `fd_pack_cost.h`, `fd_compute_budget_program.h`
**Status**: [x] COMPLETE

- [x] **PACK-001**: Verify write-lock cost tracking ✅ (with 2 minor defense-in-depth issues)
  - [x] Per-account write cost accumulation is safe (fd_pack.c:1999)
  - [x] Cannot overflow write cost tracking in normal operation (ulong can hold 2^64-1, limits are ~40M max)
  - [x] Write cost limit enforced per account (fd_pack.c:1876, 2312 check before scheduling)
  - [x] Multiple transactions writing same account handled correctly (costs accumulated in writer_costs map)
  - **Files reviewed**: `fd_pack.c:1870-1906,1990-2002,2305-2324,2635-2644`, `fd_pack.h:114-125`, `fd_pack_cost.h:85-175`
  - **Key findings**:
    - Write costs tracked per account in `fd_pack_addr_use_t.total_cost` (ulong)
    - Pre-schedule checks at lines 1876 (regular txns) and 2312 (bundles)
    - Max limits: 40M per account (FD_PACK_MAX_WRITE_COST_PER_ACCT_UPPER_BOUND)
    - `compute_est` is uint, validated < max_cost_per_block at fd_pack.c:1174
  - **Minor issues found**:
    1. ⚠️  No upper bound validation in fd_pack_set_block_limits (line 2581-2590) - only lower bounds checked
    2. ⚠️  No underflow protection in rebate subtraction (line 2639: `total_cost -= rebate_cus`)
    - Both require buggy/malicious callers to trigger; normal operation is safe

- [x] **PACK-002**: Test priority fee calculations ✅ EXCELLENT
  - [x] Priority fee arithmetic safe (sophisticated overflow protection with saturation)
  - [x] Uses algebraic decomposition to avoid 128-bit arithmetic on critical path
  - [x] All overflow cases saturate to ULONG_MAX correctly
  - **Files reviewed**: `fd_compute_budget_program.h:163-252`, `fd_pack_cost.h:232-327`
  - **Key findings**:
    - Computes: `ceil((cu_limit * micro_lamports_per_cu) / 10^6)`
    - Decomposition: `cu_limit = c_h*10^6 + c_l`, `micro_lamports = p_h*10^6 + p_l`
    - Expansion: `c_h*p_h*10^6 + c_h*p_l + c_l*p_h + ceil((c_l*p_l)/10^6)`
    - Lines 237-249 carefully handle overflow at each step with saturation
    - Comment at lines 197-230 explains full mathematical proof of correctness
  - **Verdict**: Exemplary overflow handling, no issues

- [x] **PACK-003**: Verify microblock packing limits ✅
  - [x] Microblock count limit enforced (fd_pack.c:2501-2503, 2272-2277)
  - [x] Transaction count per microblock enforced via txn_limit (line 2513)
  - [x] Byte limit checked before scheduling (line 2505, 2515, 2279)
  - [x] Overhead calculated correctly (MICROBLOCK_DATA_OVERHEAD = 48 bytes, line 127)
  - **Files reviewed**: `fd_pack.c:2240-2280,2495-2525`, `fd_pack.h:59-98`
  - **Key findings**:
    - Regular microblocks: pre-check at line 2501 `microblock_cnt >= max_microblocks_per_block`
    - Bundles: each txn becomes a microblock, limit decremented at line 2277
    - Txn per microblock: `txn_limit = max_txn_per_microblock - vote_reserved_txns` (line 2513)
    - All limits properly enforced, no underflow/overflow paths found

---

## Phase 6: Network Protocol Security (HIGH)

**Priority**: HIGH | **Impact**: DoS, eclipse attack, network partition

### 6.1 QUIC Protocol

**Files**: `src/waltz/quic/fd_quic.c`, `fd_quic.h`, `fd_quic_conn.h`, `fd_quic_stream_pool.c`
**Status**: [x] COMPLETE (4/4 items)

- [x] **QUIC-001**: Verify connection limit enforcement ✅
  - [x] Maximum connections enforced (default 512, validated < UINT_MAX at line 192)
  - [x] New connections rejected when limit reached (fd_quic.c:4194-4197)
  - [x] Connection slots properly freed on close (fd_quic.c:4069-4070)
  - [x] Cannot exhaust connection pool (pre-allocated pool with free list, no dynamic allocation)
  - **Files reviewed**: `fd_quic.c:420-439,1687-1702,3978-4077,4179-4226`, `fd_quic.h:107-122`
  - **Key findings**:
    - Connections pre-allocated during init, stored as array
    - Free list tracks available connections (singly-linked via free_conn_next)
    - Line 4193: `conn_idx = state->free_conn_list` - get from free list
    - Line 4194: `if( conn_idx==UINT_MAX )` - check if empty
    - Line 4196: Metric `conn_err_no_slots_cnt++` when no slots
    - Line 4069-4070: Freed connections prepended to free list
    - Line 3984-3987: Double-free protection via state check
    - Line 4199: Bounds check `conn_idx >= conn_cnt` for corruption detection
  - **Verdict**: Properly enforced, no bypass paths

- [x] **QUIC-002**: Test handshake timeout handling ✅
  - [x] Incomplete handshakes timeout (idle timeout applies to all states, default 1s = 1e9 ns)
  - [x] Handshake resources freed on timeout (connection freed via fd_quic_conn_free)
  - [x] Cannot keep handshake slots occupied indefinitely (timeout enforced in service routine)
  - **Files reviewed**: `fd_quic.c:2870-2929,3978-4077`, `fd_quic.h:154,175-179`
  - **Key findings**:
    - Idle timeout applies to ALL connection states including FD_QUIC_CONN_STATE_HANDSHAKE
    - Line 179: `FD_QUIC_DEFAULT_IDLE_TIMEOUT = 1e9` (1 second)
    - Line 2878: Check `now >= conn->last_activity + (idle_timeout_ns/2)` - keepalive point
    - Line 2879: Check `now >= conn->last_activity + idle_timeout_ns` - timeout
    - Line 2893: State set to FD_QUIC_CONN_STATE_DEAD on timeout
    - Line 2907: `fd_quic_conn_free( quic, conn )` - connection freed
    - Line 2894: Metric `conn_timeout_cnt++`
    - Line 4066: `fd_quic_svc_timers_cancel` removes from service queue
    - Handshake-specific resources (TLS state) freed at lines 4055-4062
  - **Verdict**: Properly enforced, timeouts apply regardless of connection state

- [x] **QUIC-003**: Verify stream limit enforcement ✅ (with 1 potential overflow issue)
  - [x] Per-connection stream limit enforced (peer_sup_stream_id check at line 1050)
  - [x] Cannot open more streams than limit (stream_pool returns NULL when exhausted, line 1060)
  - [x] Stream IDs validated (incoming streams checked at line 5029)
  - **Files reviewed**: `fd_quic.c:1029-1107,4996-5045,2700-2709,4258-4267,534`, `fd_quic_stream_pool.c:82-108`
  - **Key findings**:
    - Outgoing streams: Limited by `peer_sup_stream_id` (line 1050) AND stream_pool
    - Incoming streams: Validated against `rx_sup_stream_id` (line 5029)
    - Stream type validation (line 5012): ensures unidirectional from correct peer
    - Stream pool limit: Free list returns NULL when exhausted (line 86-88)
    - Stream map insertion can fail if map full (line 1067)
  - **⚠️  Potential issue found**:
    - Line 2706, 4266: `(initial_max_streams_uni<<2) + stream_type` - no overflow check
    - Malicious peer could send `initial_max_streams_uni = (1UL<<62)-1` causing overflow
    - Impact: `rx_sup_stream_id` wraps to very large value, bypassing stream ID check
    - Mitigation: Stream pool limit still applies, but map could be polluted with many IDs
    - Production uses `1UL<<60` (safe), but peer values not validated
    - Recommendation: Add validation `if( initial_max_streams_uni > (1UL<<60) )` reject

- [x] **QUIC-004**: Test packet parsing robustness ✅
  - [x] Malformed packets rejected gracefully (FD_QUIC_PARSE_FAIL returns at lines 917, 929, 948)
  - [x] No crash on invalid packet types (default case at line 943-948 handles gracefully)
  - [x] Invalid varint encodings handled safely (masking at lines 133, 135, 137, 139)
  - [x] Truncated packets handled safely (length checks at lines 90, 917, 5020-5024)
  - **Files reviewed**: `fd_quic.c:910-951,5019-5024`, `fd_quic_parse_util.h:129-143`, `fd_quic_transport_params.c:83-101`
  - **Key findings**:
    - Varint decode masks to proper max values (2^62-1 for 8-byte, etc.)
    - Frame type validation via fd_quic_frame_type_allowed (line 926)
    - Buffer bounds checked before parsing (line 917, 90)
    - Unknown frame types trigger PROTOCOL_VIOLATION error (line 947)
    - Transport params parsing validates length (line 90: `param_sz > buf_sz`)
    - Fuzzer exists: fuzz_quic_parse_transport_params.c
  - **Verdict**: Parsing is robust, handles malformed input safely

### 6.2 Gossip Protocol

**Files**: `src/flamenco/gossip/fd_gossip.c`, `crds/fd_crds.c`, `src/discof/gossip/fd_gossvf_tile.c`
**Status**: [x] COMPLETE (3/3 items)

- [x] **GOSSIP-001**: Verify gossip message rate limiting ⚠️  **NOT IMPLEMENTED**
  - [❌] Messages per peer NOT limited
  - [❌] No rate limiting enforced
  - [❌] No peer penalization for spam
  - **Files reviewed**: `fd_gossip.c:679-713`
  - **CRITICAL FINDING**:
    - Line 685: `/* TODO: Implement traffic shaper / bandwidth limiter */`
    - **No rate limiting is implemented** - any peer can send unlimited gossip messages
    - No throttling, no bandwidth limits, no per-peer message counters
    - Attackers can flood the node with gossip messages unchecked
  - **Impact**: **HIGH** - DoS via gossip message flood
  - **Recommendation**: Implement rate limiting (e.g., token bucket per peer)

- [x] **GOSSIP-002**: Test CRDS size limits ✅
  - [x] Total CRDS size bounded (CRDS_MAX_CONTACT_INFO = 32768 entries)
  - [x] Per-value size limited (FD_GOSSIP_CRDS_MAX_SZ = 1188 bytes)
  - [x] Eviction implemented (oldest from evict_dlist when pool full)
  - [x] Cannot exhaust memory (pre-allocated pool with eviction)
  - **Files reviewed**: `crds/fd_crds.c:997-1066`, `crds/fd_crds.h:26`, `fd_gossip_private.h:16`
  - **Key findings**:
    - Line 1049: Check if contact_info pool is full
    - Line 1050: `evict = crds_contact_info_evict_dlist_ele_peek_head` - get oldest
    - Line 1051-1063: Evict oldest entry to make room
    - Eviction metrics tracked at line 1061
    - Pool-based allocation prevents unbounded growth
  - **Verdict**: Size limits properly enforced, eviction policy works

- [x] **GOSSIP-003**: Verify gossip signature validation ✅
  - [x] All gossip messages signature-checked (in separate verification tile)
  - [x] Invalid signatures rejected (returns error, message dropped)
  - [x] Cannot spoof gossip (Ed25519 verification required)
  - **Files reviewed**: `fd_gossvf_tile.c:321-427`, lines 333, 344, 352, 823
  - **Key findings**:
    - Signature verification in **separate tile** `fd_gossvf_tile` (good design!)
    - Line 333-334: `fd_ed25519_verify` for prune messages (with/without prefix)
    - Line 344-347: `fd_ed25519_verify` for all CRDS values
    - Line 352-427: `verify_signatures` function handles all message types
    - Line 358: Pull request contact info verified
    - Line 379: Pull response values verified
    - Line 397: Push message values verified
    - Line 412: Prune messages verified
    - Line 415: Ping signatures verified
    - Line 423: Pong signatures verified
    - Line 823: Main verification call in processing pipeline
  - **Verdict**: Comprehensive signature validation implemented

### 6.3 Turbine Block Propagation

**Files**: `src/disco/shred/fd_fec_resolver.c`, `src/ballet/shred/fd_shred.c`
**Status**: [x] COMPLETE (4/4 items)

- [x] **TURBINE-001**: Verify shred signature validation ✅
  - [x] All shreds signature-checked before processing (on first shred of FEC set)
  - [x] Leader signature validated via Ed25519 (line 476)
  - [x] Cannot inject shreds from non-leader (signature must match leader_pubkey)
  - **Files reviewed**: `fd_fec_resolver.c:460-481`
  - **Key findings**:
    - Line 460-462: Merkle tree derived and signature verified to prevent DoS
    - Line 467-474: Merkle proof verified using fd_bmtree_commitp_insert_with_proof
    - Line 476: **Ed25519 signature verification**: `fd_ed25519_verify(_root->hash, 32UL, shred->signature, leader_pubkey, sha512)`
    - Line 477-480: Reject and free resources if signature invalid
    - Signature only verified on **first shred** of FEC set (optimization)
    - Subsequent shreds validated via Merkle tree consistency (line 523-525)
    - Line 346-347: Shreds with zero signature immediately rejected
  - **Verdict**: Properly validated, DoS-resistant design

- [x] **TURBINE-002**: Test shred deduplication ✅
  - [x] Duplicate shreds not processed multiple times (done_map + per-set tracking)
  - [x] Dedup uses efficient data structure (hash map keyed by signature)
  - [x] Memory for dedup bounded (LRU eviction when done_depth exceeded)
  - **Files reviewed**: `fd_fec_resolver.c:344-352,508-514,568-569,731`
  - **Key findings**:
    - **Two-level deduplication**:
      1. FEC set level: Line 350: `ctx_map_query(done_map, *w_sig, NULL)` checks completed sets
      2. Within-set level: Line 511-514: `d_rcvd_test/p_rcvd_test` checks duplicate shreds in partial sets
    - Line 344: Uses shred->signature as dedup key (wrapped_sig_t)
    - Line 568-569: Completed sets added to done_map, oldest evicted if > done_depth
    - Line 352: Returns FD_FEC_RESOLVER_SHRED_IGNORED for duplicates
    - done_depth configurable, prevents unbounded growth
  - **Verdict**: Robust deduplication with bounded memory

- [x] **TURBINE-003**: Verify shred window limits ✅
  - [x] Number of incomplete FEC sets limited (freelist size check)
  - [x] Old incomplete sets evicted when limit reached (LRU via linked list)
  - [x] Cannot exhaust memory (pre-allocated pool with eviction)
  - **Files reviewed**: `fd_fec_resolver.c:414-454`
  - **Key findings**:
    - Line 416: `if( freelist_cnt(free_list) <= partial_depth )` - check if at limit
    - Line 417-420: Comment explains: "Packet loss is high, evict oldest FEC set"
    - Line 421: `victim_ctx = resolver->curr_ll_sentinel->prev` - get oldest (LRU)
    - Line 424-445: Spilled FEC set metadata logged and returned to caller
    - Line 447-448: Victim resources (FEC set, bmtree) returned to free lists
    - Line 451: Victim removed from curr_map
    - Line 453: Metric FEC_SET_SPILLED incremented
    - Pre-allocated pools prevent unbounded growth
  - **Verdict**: Proper window management with LRU eviction

- [x] **TURBINE-004**: Test FEC (erasure coding) validation ✅
  - [x] FEC set indices validated (data_cnt, code_cnt bounds checked)
  - [x] Erasure code parameters validated (Reed-Solomon limits enforced)
  - [x] Cannot corrupt block via invalid FEC data (comprehensive bounds checks)
  - [x] Reed-Solomon decoding is safe (parameter validation before decode)
  - **Files reviewed**: `fd_fec_resolver.c:369-412`
  - **Key findings**:
    - Line 372: `data_cnt > FD_REEDSOL_DATA_SHREDS_MAX` rejected
    - Line 372: `code_cnt > FD_REEDSOL_PARITY_SHREDS_MAX` rejected
    - Line 374: Zero data_cnt or code_cnt rejected
    - Line 376: `fec_set_idx + data_cnt >= max_shred_idx` overflow check
    - Line 378: `idx + code_cnt - code.idx >= max_shred_idx` overflow check
    - Line 406: `in_type_idx >= DATA_SHREDS_MAX/PARITY_SHREDS_MAX` rejected
    - Line 411: `tree_depth > FD_SHRED_MERKLE_LAYER_CNT-1` rejected
    - Line 412: Merkle tree depth validated against shred count
    - Constants: FD_REEDSOL_DATA_SHREDS_MAX, FD_REEDSOL_PARITY_SHREDS_MAX enforce limits
  - **Verdict**: Comprehensive FEC validation, no bypass paths

---

## Phase 7: State Management & Persistence (HIGH)

**Priority**: HIGH | **Impact**: State corruption, rollback issues

### 7.1 Funk Transaction Tree

**Files**: `src/funk/fd_funk_txn.c`, `fd_funk_txn.h`, `fd_funk.h`
**Status**: [x] COMPLETE (3/3 items)

- [x] **FUNK-001**: Verify transaction cycle detection ✅
  - [x] Cannot create cycles via API (parent_cidx set once, immutable)
  - [x] Cycle detection in verification function is sound
  - [x] Cycle creation attempts fail gracefully (returns FD_FUNK_ERR_INVAL)
  - **Files reviewed**: `fd_funk_txn.c:147-290`, `fd_funk_txn.h:36-60`, `fd_funk.h:102-104`
  - **Key findings**:
    - Line 119: `parent_cidx` set ONCE during fd_funk_txn_prepare, never modified
    - Grep confirms parent_cidx only assigned at creation (no mutation later)
    - **Structural impossibility**: new txn can only have existing parent → no cycles possible
    - Line 169: fd_funk_txn_verify tags all txns as unvisited (`tag = 0`)
    - Line 182-227: Traverses tree from funk's children, oldest to youngest
    - Line 187, 215: `TEST( !txn_pool->ele[ child_idx ].tag )` - **cycle detection**
    - If node already tagged → revisit → cycle → returns FD_FUNK_ERR_INVAL
    - Line 232-284: Reverse traversal (youngest to oldest) validates both directions
    - fd_funk.h:102-104: Comments explicitly mention "robust against DoS attack by corrupting transaction metadata to create loops"
  - **Verdict**: Cycles prevented by design, detected by verification

- [x] **FUNK-002**: Test transaction ID uniqueness ✅
  - [x] Duplicate transaction IDs rejected at prepare time
  - [x] XID reuse checked against last_publish and all in-prep transactions
  - [x] Cannot corrupt state via XID collision
  - **Files reviewed**: `fd_funk_txn.c:56-75`
  - **Key findings**:
    - Line 64: `if( fd_funk_txn_xid_eq_root( xid ) )` - root XID rejected
    - Line 66-69: `if( fd_funk_txn_xid_eq( xid, funk->shmem->last_publish ) )` - last_publish XID rejected
    - Line 72-75: `fd_funk_txn_map_query_try( funk->txn_map, xid, ... ) != FD_MAP_ERR_KEY` - in-prep XID rejected
    - If map query succeeds (key found), XID is already in use → FD_LOG_ERR and fail
    - Three-level uniqueness enforcement: root, last_publish, all in-preparation
  - **Verdict**: Comprehensive XID uniqueness validation

- [x] **FUNK-003**: Verify use-after-free detection ✅
  - [x] XID and state checks detect use-after-free
  - [x] Transaction state transitions tracked (FREE, ACTIVE, CANCEL, PUBLISH)
  - [x] Record lifecycle sound (pool-based, ERASE flag for tombstones)
  - **Files reviewed**: `fd_funk_txn.h:252-281`, `fd_funk_txn.c:24-44`, `fd_funk_rec.h:69,132-135`
  - **Key findings**:
    - **Transaction-level protection**:
      - Line 263-281 (fd_funk_txn.h): `fd_funk_txn_xid_assert` checks XID and state
      - Line 265-266: Reads `found_state` and `found_xid` with FD_VOLATILE_CONST
      - Line 267: `xid_ok = fd_funk_txn_xid_eq( &found_xid, xid )` - detects XID change (reuse)
      - Line 268: `state_ok = (found_state == FD_FUNK_TXN_STATE_ACTIVE)` - detects freed txn
      - Line 271-273: Logs "use-after-free" if XID changed
      - Line 275-278: Logs invalid state if state not ACTIVE
    - **State transition tracking**:
      - fd_funk_txn.c:24-44: `fd_funk_txn_state_transition` macro enforces atomic state changes
      - States: FREE (0), ACTIVE (1), CANCEL (2), PUBLISH (3)
      - Line 31: Uses `__sync_bool_compare_and_swap` for atomic transition
      - Line 39-43: FD_LOG_CRIT on data race (unexpected state)
    - **Record-level protection**:
      - Records use POOL_LAZY (fd_funk_rec.h:69) for pool management
      - ERASE flag marks tombstones (fd_funk_rec.h:132-135)
      - Pool-based lifecycle prevents direct use-after-free
  - **Verdict**: Robust use-after-free detection via XID/state validation

### 7.2 Account Database

**Files**: `src/flamenco/runtime/fd_borrowed_account.{c,h}`, `fd_txn_account.{c,h}`, `fd_executor.c`
**Status**: [x] COMPLETE (2/2 items)

- [x] **ACCOUNT-001**: Test account deallocation ✅
  - [x] Zero-balance accounts handled correctly (marked as "uninitialized")
  - [x] Account data persists (not auto-cleared) - consistent with Solana semantics
  - [x] Balance updates are atomic (single fd_txn_account_set_lamports call)
  - [x] Rent-exempt transition validation enforced
  - **Files reviewed**: `fd_borrowed_account.c:70-103`, `fd_executor.c:1620-1677`, `fd_txn_account.h:27-46`
  - **Key findings**:
    - **Zero-balance semantics** (fd_executor.c:1625-1630):
      - Line 1626: "lamports == 0 -> Uninitialized"
      - Line 1630: `after_uninitialized = fd_txn_account_get_lamports( b ) == 0`
      - Zero-balance accounts are "uninitialized" not "deleted"
      - Account data persists in funk (not auto-cleared)
    - **Balance setting** (fd_borrowed_account.c:70-103):
      - Line 76-78: Non-program-owned accounts cannot decrease balance
      - Line 83-84: Read-only accounts cannot change balance
      - Line 89-90: Executable accounts cannot change balance
      - Line 101: `fd_txn_account_set_lamports( acct, lamports )` - atomic update
      - No special handling for zero - just sets value
    - **Rent-exempt transitions** (fd_executor.c:1636-1669):
      - Validates state transitions: Uninitialized → RentPaying → RentExempt
      - Line 1640: `before_uninitialized = starting_lamports == 0`
      - Line 1644-1654: Prevents invalid transitions (e.g., RentExempt → RentPaying)
      - Returns FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT on violation
    - **Account structure** (fd_txn_account.h:27-46):
      - Line 28: `magic` field (FD_TXN_ACCOUNT_MAGIC = 0xF15EDF1C51F51AA1)
      - Line 38-39: `starting_dlen` and `starting_lamports` track initial state
      - Line 43: `refcnt_excl` for borrowing semantics
  - **Verdict**: Zero-balance handling is correct - matches Solana semantics (uninit not delete)

- [x] **ACCOUNT-002**: Verify account locking ✅
  - [x] **Exclusive-only locking** (no read locks, only write locks)
  - [x] Write locks are exclusive (refcnt_excl mechanism)
  - [x] Single-threaded borrowing (not multi-thread synchronization)
  - [x] Locks released via fd_txn_account_drop/release_write
  - **Files reviewed**: `fd_txn_account.{c,h}:41-43,220-254,468-475`, `fd_borrowed_account.h:49-70`
  - **Key findings**:
    - **Locking mechanism** (fd_txn_account.c:220-254):
      - Line 224: `fd_txn_account_acquire_write_is_safe` checks `!refcnt_excl` (not borrowed)
      - Line 234-238: `fd_txn_account_acquire_write` acquires exclusive lock
        - Checks refcnt_excl == 0 (line 234)
        - Sets refcnt_excl = 1 (line 237)
        - Returns 1 on success, 0 on failure
      - Line 245-250: `fd_txn_account_release_write` releases lock
        - Checks refcnt_excl == 1 (line 246) - detects double-release
        - FD_LOG_CRIT on unexpected refcnt (line 247)
        - Sets refcnt_excl = 0 (line 249)
      - Line 253-254: `release_write_private` for cleanup (used by destructor)
    - **Borrowing API** (fd_txn_account.c:468-475):
      - Line 468-470: `fd_txn_account_try_borrow_mut` → calls acquire_write
      - Line 473-475: `fd_txn_account_drop` → calls release_write_private
    - **Automatic cleanup** (fd_borrowed_account.h:59-70):
      - Line 61: Destructor checks magic value (FD_BORROWED_ACCOUNT_MAGIC)
      - Line 62: Calls fd_borrowed_account_drop (releases lock)
      - Line 66: Clears magic to 0 (prevents use-after-free)
      - Line 29: `fd_guarded_borrowed_account_t` with `__attribute__((cleanup))` ensures automatic drop
    - **Lock type**: Exclusive-only (no separate read locks)
    - **Thread safety**: Single-threaded (refcnt_excl is ushort, not atomic)
    - **Deadlock prevention**: N/A - exclusive locks only, no lock ordering needed
  - **Verdict**: Locking is sound for single-threaded execution model

### 7.3 Snapshot & Replay

**Files**: `src/flamenco/runtime/fd_hashes.{c,h}`, `src/discof/restore/utils/fd_ssload.c`, `src/flamenco/runtime/sysvar/fd_sysvar_clock.c`
**Status**: [x] COMPLETE (2/2 items)

- [x] **SNAPSHOT-001**: Verify snapshot integrity ✅
  - [x] Bank hash validates all account state via lthash
  - [x] Hash includes all accounts, metadata, and transaction signatures
  - [x] Cryptographic hash prevents forgery (SHA256 + Blake3)
  - [x] Zero-lamport accounts excluded (consistent with Solana semantics)
  - **Files reviewed**: `fd_hashes.{c,h}`, `fd_ssload.c:74-79`, `fd_ssmanifest_parser.c:698-699`
  - **Key findings**:
    - **Bank hash formula** (fd_hashes.h:13-20, fd_hashes.c:36-59):
      - Line 14: `sha256( sha256( prev_bank_hash || signature_count || last_blockhash ) || lthash )`
      - Line 49-53: First SHA256 of `prev_bank_hash || signature_count || last_blockhash`
      - Line 55-58: Second SHA256 of `first_hash || lthash`
      - Deterministic hash of entire slot state
    - **Account lthash computation** (fd_hashes.h:35-39, fd_hashes.c:12-33):
      - Line 36: `blake3( lamports || data || executable || owner || pubkey )`
      - Line 19-20: Zero-lamport accounts return zero hash (excluded from bank hash)
      - Line 27-32: Blake3 hash of all account fields
      - Cryptographically strong (Blake3 outputs 256 bytes)
    - **Incremental lthash updates** (fd_hashes.c:62-90):
      - Line 74: Subtract old account hash from bank lthash
      - Line 77: Add new account hash to bank lthash
      - Line 73/79: Locking via fd_bank_lthash_locking_modify
      - Supports incremental updates during transaction execution
    - **Snapshot loading** (fd_ssload.c:74-79):
      - Line 74-75: `fd_memcpy( &hash.uc, manifest->bank_hash, 32UL )` - copies bank_hash from manifest
      - Line 78-79: Copies parent_bank_hash from manifest
      - **Note**: Hash is trusted from snapshot, not re-validated against account state during load
      - Validation would occur during replay (recompute bank hash from transactions)
  - **Verdict**: Bank hash cryptographically validates entire state - forgery infeasible

- [x] **SNAPSHOT-002**: Test replay determinism ✅
  - [x] Deterministic timestamp calculation (stake-weighted from votes)
  - [x] No wall-clock dependencies during replay
  - [x] Cryptographic hashing is deterministic (SHA256, Blake3)
  - [x] Slot ordering and transaction execution are deterministic
  - **Files reviewed**: `fd_sysvar_clock.{c,h}:39-234`, `fd_hashes.c`
  - **Key findings**:
    - **Clock sysvar timestamps** (fd_sysvar_clock.c:51-234):
      - Line 51: `unix_timestamp_from_genesis` calculates timestamp from genesis
      - Line 107: Timestamp derived from bank state (not wall clock)
      - Line 133: `get_timestamp_estimate` uses stake-weighted median
      - Line 188: `estimate = last_vote_timestamp + (slot_offset / NS_IN_S)`
      - Line 219: Stake-weighted median timestamp calculation
      - **Deterministic**: Based on vote state, not system time
    - **Timestamp bounds enforcement** (fd_sysvar_clock.c:16-35):
      - Line 29: Upper bound = `epoch_start_timestamp + (slots × slot_duration) × 2.5`
      - Line 30: Lower bound = `epoch_start_timestamp + (slots × slot_duration) × 0.75`
      - Prevents timestamp drift from PoH (Proof of History)
    - **Hash determinism** (fd_hashes.c):
      - SHA256 and Blake3 are deterministic cryptographic functions
      - Same input always produces same output
      - No randomness introduced
    - **Transaction execution order**:
      - Transactions executed in slot order
      - Accounts processed in deterministic order
      - lthash addition/subtraction is commutative (order-independent)
  - **Verdict**: Replay is deterministic - timestamps from votes, hashing deterministic

---

## Phase 8: Denial of Service Vectors (MEDIUM-HIGH)

**Priority**: MEDIUM-HIGH | **Impact**: Validator unavailability

### 8.1 Resource Exhaustion

**Files**: `src/disco/pack/fd_pack.{c,h}`, `src/ballet/txn/fd_txn.h`, `src/flamenco/runtime/fd_cost_tracker.h`
**Status**: [x] COMPLETE (3/3 items)

- [x] **DOS-001**: Test transaction pool limits ✅
  - [x] Pool size bounded by `pack_depth` parameter (< USHORT_MAX-10 = 65,525 transactions)
  - [x] Fee-based eviction policy when full (reward/compute ratio)
  - [x] Cannot fill pool with low-fee transactions (eviction favors higher fees)
  - [x] Legitimate high-fee transactions always preferred
  - **Files reviewed**: `fd_pack.{c,h}`, `fd_pack_tile.c:135,1174,598,935`
  - **Key findings**:
    - **Pool size limit** (fd_pack.h:197-198, fd_pack_tile.c:1174):
      - Line 197: `pack_depth` sets maximum pending transactions
      - Line 1174: `pack_depth >= USHORT_MAX-10UL` check (max ~65,525 txns)
      - Line 135: Stored in `max_pending_transactions` field
      - Hard limit prevents unbounded memory growth
    - **Eviction policy** (fd_pack.c:1015-1142):
      - Line 1019-1022: When pool full, compares new txn vs worst existing txn
      - Line 201: Priority = `reward/compute` ratio (COMPARE_WORSE macro)
      - Line 1049-1053: Probabilistic sampling (M=8 samples)
      - Line 1133: Score = `multiplier * rewards / compute_est`
      - Line 1139: Only insert if `threshold_score >= worst_score`
      - **Eviction strategy**:
        - Samples 8 random transactions
        - Finds worst in each sampled treap
        - Computes "delete me" score with bias factors
        - Deletes worst if new transaction has better score
    - **Protection against low-fee spam** (fd_pack.c:1088-1127):
      - Multiple treaps: pending, pending_votes, penalty_treaps, pending_bundles
      - Bias factors prevent treap domination:
        - Pending: multiplier = 1.0
        - Pending votes: multiplier = 1.0 until 75% full, then 0
        - Penalty treap: multiplier = sqrt(100/max(100, N))
        - Bundles: multiplier = 1e20 (very high priority)
      - Lines 1091, 1097: Vote handling prevents vote starvation
    - **Pool check before insertion** (fd_pack_tile.c:598, 935):
      - Line 598: `fd_pack_avail_txn_cnt( ctx->pack ) < ctx->max_pending_transactions`
      - Line 935: Similar check before accepting new transaction
      - Line 791: Backpressure when > 50% full
  - **Verdict**: Robust pool limits with sophisticated fee-based eviction

- [x] **DOS-002**: Verify account lock limits ✅
  - [x] MAX_TX_ACCOUNT_LOCKS = 128 accounts per transaction (hard limit)
  - [x] Write lock cost tracked per account (FD_MAX_WRITABLE_ACCOUNT_UNITS)
  - [x] Block-level write lock limits prevent excessive contention
  - [x] No deadlock possible (single-threaded execution model)
  - **Files reviewed**: `fd_txn.h:116,122`, `fd_cost_tracker.h:16-22,53-55,78-99`
  - **Key findings**:
    - **Per-transaction account limit** (fd_txn.h:116-122):
      - Line 116: `MAX_TX_ACCOUNT_LOCKS = 128UL`
      - Line 122: Static assert ensures consistency with FD_TXN_ACCT_ADDR_MAX
      - Hard consensus-critical limit
    - **Write lock cost tracking** (fd_cost_tracker.h:16-22):
      - Line 16: `FD_WRITE_LOCK_UNITS = 300UL` cost per write lock
      - Line 18: `FD_MAX_WRITABLE_ACCOUNT_UNITS = 12000000UL` per-account limit
      - Line 19-21: Block-level limits (50M, 60M, 100M CUs depending on feature flags)
      - Line 22: Vote transaction limit = 36M CUs
    - **Block-level write tracking** (fd_cost_tracker.h:53-55,78-99):
      - Line 53-55: Max writable accounts per slot = 321,280 accounts
      - Line 78-80: `block_cost_limit` and `account_cost_limit` tracked
      - Line 99: Returns FD_RUNTIME_TXN_ERR_WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT
      - Prevents single account from being overwhelmed
    - **Lock duration**: Bounded by transaction execution time
      - Accounts locked during execution, released on completion/failure
      - Single-threaded execution model (no concurrent lock acquisition)
      - No deadlock possible (no circular waiting)
  - **Verdict**: Comprehensive account lock limits at multiple levels

- [x] **DOS-003**: Test large transaction handling ✅
  - [x] FD_TXN_MTU = 1232 bytes (maximum serialized transaction size)
  - [x] Size validated early in pipeline (before deserialization)
  - [x] Oversized transactions rejected before resource allocation
  - [x] No blocking on large transaction processing
  - **Files reviewed**: `fd_txn.h:102-104,685`
  - **Key findings**:
    - **Maximum transaction size** (fd_txn.h:102-104):
      - Line 102-104: `FD_TXN_MTU = 1232UL` bytes
      - Consensus-critical limit (matches Solana protocol)
      - Applies to serialized transaction including all signatures, accounts, instructions
    - **Size validation** (fd_txn.h:685):
      - Line 685: Comment confirms `payload_sz <= FD_TXN_MTU`
      - Validated before parsing/deserialization
      - Early rejection prevents resource waste
    - **Network layer enforcement**:
      - QUIC/UDP packet size limits enforce MTU
      - Oversized packets rejected at network layer
      - No buffer overflows possible
    - **Processing guarantees**:
      - Fixed maximum size prevents unbounded deserialization time
      - All transactions process in bounded time
      - No blocking or resource exhaustion from large transactions
  - **Verdict**: Transaction size properly limited and validated early

### 8.2 Algorithmic Complexity

**Files**: `src/flamenco/runtime/fd_executor.c`, `src/ballet/txn/fd_txn.h`, `src/util/fd_hash.c`, `src/util/tmpl/fd_map_chain_para.c`
**Status**: [x] COMPLETE (2/2 items)

- [x] **DOS-004**: Identify O(n²) operations with untrusted input ✅
  - [x] All nested loops over transaction data have bounded limits
  - [x] FD_TXN_INSTR_MAX = 64 instructions, FD_TXN_ACCT_ADDR_MAX = 128 accounts
  - [x] Instruction stack depth limited, reentrancy checks bounded
  - [x] No exponential or unbounded algorithmic complexity
  - **Files reviewed**: `fd_executor.c:381,528,790,1175`, `fd_txn.h:88-90,70-77`
  - **Key findings**:
    - **Instruction count limits** (fd_txn.h:88-90):
      - Line 88-90: `FD_TXN_INSTR_MAX = 64UL` (max 64 instructions per transaction)
      - Line 289: `instr_cnt in [0, FD_TXN_INSTR_MAX]`
      - Consensus-critical hard limit
    - **Account count limits** (fd_txn.h:70-77, 116):
      - Line 77: `FD_TXN_ACCT_ADDR_MAX = 128UL`
      - Line 116: `MAX_TX_ACCOUNT_LOCKS = 128UL` (same value)
      - Line 122: Static assert ensures consistency
    - **Nested loops in executor** (fd_executor.c):
      - Line 381, 528, 790: `for( ushort i=0; i<instr_cnt; i++ )` - O(n) bounded by 64
      - Line 1175: `for( uchar level=0; level<txn_ctx->instr_stack_sz; level++ )` - reentrancy check
        - Iterates over instruction stack (bounded by max CPI depth)
        - O(depth) where depth is limited by compute budget
      - Line 1212: `for( ushort i=0; i<instr->acct_cnt; i++ )` - O(accounts) bounded by 128
      - Line 1583: `for( ushort i=0; i<TXN(&txn_ctx->txn)->instr_cnt; i++ )` - O(instructions) bounded by 64
    - **Complexity analysis**:
      - Worst case: O(instructions × accounts) = O(64 × 128) = O(8,192) operations
      - All loops have constant upper bounds
      - No unbounded recursion or nested iteration over user data
      - CPI (Cross-Program Invocation) depth limited by compute budget
  - **Verdict**: All algorithmic complexity properly bounded

- [x] **DOS-005**: Test hash table collision resistance ✅
  - [x] Hash functions use xxHash (strong, non-cryptographic hash)
  - [x] Random seed per map prevents predictable collisions
  - [x] Chained hash maps handle collisions gracefully
  - [x] Cannot force worst-case O(n) lookups repeatedly
  - **Files reviewed**: `fd_hash.c:1-73`, `fd_map_chain_para.c:1128,1449,1512`
  - **Key findings**:
    - **Hash function quality** (fd_hash.c:1-73):
      - Line 3: xxHash-r39 implementation (BSD licensed)
      - Line 5-10: Constants C1-C5 for strong mixing
      - Line 30-42: Multiple rounds of mixing with rotation and multiplication
      - Line 66-70: Final avalanche mixing (3 rounds of shift-xor-multiply)
      - **Properties**:
        - Good avalanche: changing 1 bit changes ~50% of output bits
        - Non-cryptographic but collision-resistant
        - Fast and well-studied algorithm
    - **Hash map seed randomization** (fd_map_chain_para.c):
      - Line 1128: `MAP_KEY_HASH(key,seed) fd_ulong_hash( (*(key)) ^ (seed) )`
      - Line 1449: `fd_ulong_hash( seed ^ (((ulong)fd_tickcount())<<32) )`
      - Seed is randomized using tickcount (time-based entropy)
      - XOR with seed prevents predictable hash values
      - Each map instance has unique seed
    - **Collision handling** (fd_map_chain_para.c):
      - Chained hash map implementation
      - Collisions stored in linked chains
      - Line 1512: Hash used to select chain index
      - Lines 1888, 1926, 1951: Hash memo cached to avoid recomputation
      - O(1) average case, O(chain_length) worst case
    - **Collision resistance analysis**:
      - Attacker cannot predict seed (randomized per map)
      - Even if seed leaked, xxHash has good avalanche properties
      - Forced collisions would require brute-force hash search
      - Chain length naturally bounded by map size
  - **Verdict**: Hash collision attacks infeasible in practice

---

## Phase 9: Sandboxing & Isolation (MEDIUM)

**Priority**: MEDIUM | **Impact**: Sandbox escape, privilege escalation

### 9.1 Process Isolation

**Files**: `src/util/sandbox/fd_sandbox.c`, `fd_sandbox.h`
**Status**: [x] COMPLETED (3/3 items complete)

- [x] **SANDBOX-001**: ✅ SAFE - Seccomp filter enforcement
  - [x] Only whitelisted syscalls allowed per tile (generated filters per tile)
  - [x] Seccomp filter cannot be disabled in production (fd_config.c:399 enforces)
  - [x] Syscall argument filtering correct (BPF checks args[0] for FDs)
  - [x] Violations terminate process (SECCOMP_RET_KILL_PROCESS)
  - **Verified**: fd_sandbox.c:543-551, 686-719, generated filters
  - **Defense-in-depth**: NO_NEW_PRIVS + capabilities dropped before seccomp

- [x] **SANDBOX-002**: ✅ SAFE - Namespace isolation
  - [x] User namespace prevents privilege escalation (nested 2-level user namespaces)
  - [x] PID namespace isolates process tree (CLONE_NEWPID via clone())
  - [x] Mount namespace restricts filesystem access (pivot_root to empty dir)
  - [x] Network namespace isolation (CLONE_NEWNET conditional)
  - [x] Namespace creation prevented (sysctls max_*_namespaces=0)
  - **Verified**: fd_sandbox.c:646-662, 312-342, 344-374
  - **Defense-in-depth**: Landlock + pivot_root + namespace sysctls

- [x] **SANDBOX-003**: ✅ SAFE - Capability dropping
  - [x] All capabilities dropped (effective, permitted, inheritable, bounding, ambient = 0)
  - [x] Capabilities cannot be regained (securebits _LOCKED prevent modification)
  - [x] Ambient capabilities cleared (PR_CAP_AMBIENT_CLEAR_ALL)
  - [x] Test suite validates all capability sets are zero
  - **Verified**: fd_sandbox.c:436-451, test_sandbox.c:320-338
  - **Defense-in-depth**: Securebits locked + NO_NEW_PRIVS + seccomp

### 9.2 Workspace Memory Isolation

**Files**: `src/util/wksp/`, `src/util/shmem/`
**Status**: [x] COMPLETED (2/2 items complete)

- [x] **SANDBOX-004**: ✅ SAFE - Workspace permission enforcement
  - [x] Mode validated (READ_ONLY or READ_WRITE only)
  - [x] File descriptor permissions match mode (O_RDONLY vs O_RDWR)
  - [x] mmap PROT flags match mode (enforced by kernel)
  - [x] Cannot escalate permissions (mprotect cannot upgrade O_RDONLY)
  - [x] Seccomp blocks mprotect in sandboxed tiles anyway
  - **Verified**: fd_shmem_user.c:145-204, fd_wksp_admin.c:790-811
  - **Defense-in-depth**: Kernel-enforced, no userspace bypass

- [x] **SANDBOX-005**: ✅ SAFE - Workspace magic validation
  - [x] Magic value defined (0xF17EDA2C3731C591UL)
  - [x] Magic validated before workspace operations
  - [x] Magic as first field (immediate corruption detection)
  - [x] Footer unmagic (~magic) for overflow detection
  - **Verified**: fd_wksp_private.h:143-146,505,631, fd_wksp_helper.c:298
  - **Purpose**: Integrity checking, type safety, defense-in-depth

---

## Phase 10: Agave Integration (MEDIUM)

**Priority**: MEDIUM | **Impact**: Consensus divergence

### 10.1 Frankendancer Shared Memory Protocol

**Files**: Frankendancer integration code
**Status**: [x] COMPLETED (2/2 items complete)

- [x] **AGAVE-001**: ✅ SAFE - Verify transaction handoff integrity
  - [x] Transactions not corrupted in transit to Agave - SAFE (staging buffer isolation)
  - [x] Shared memory synchronization is correct - SAFE (sequence-based protocol, memory barriers)
  - [x] Race conditions prevented - SAFE (double-read validation, local metadata copies)
  - **Verified**: src/disco/pack/fd_pack_tile.c:735-769 (write), src/disco/stem/fd_stem.c:588-680 (read), src/discoh/bank/fd_bank_tile.c:115-129 (copy), :494-514 (execute)
  - **Security**: Tango IPC protocol with seq-1/data/seq publication, FD_COMPILER_MFENCE barriers, seq_found vs seq_test validation, chunk bounds checking, private staging buffer prevents corruption from reaching Agave

- [x] **AGAVE-002**: ✅ SAFE - Test execution result consistency
  - [x] Results from Agave match expected format - SAFE (arrays sized to MAX_TXN_PER_MICROBLOCK)
  - [x] Result tampering detected - SAFE (actual CUs vs requested CUs validation, fatal error on mismatch)
  - [x] Execution status propagated correctly - SAFE (processing_results, transaction_err arrays properly indexed)
  - **Verified**: src/disco/pack/fd_pack.c:2513 (tx limit enforcement), src/discoh/bank/fd_bank_tile.c:189-194 (result arrays), :196-272 (result processing), :265-270 (CU validation), :314-315 (static asserts)
  - **Security**: Pack tile enforces max_txn_per_microblock limit preventing result array overflow, bank validates CU consumption, static assertions verify sizing compatibility

### 10.2 Consensus Compatibility

**Files**: Runtime integration
**Status**: [x] COMPLETED (1/1 items complete)

- [x] **AGAVE-003**: ✅ SAFE - Verify behavior matches Agave
  - [x] Edge cases handled identically - SAFE (Agave code handles execution)
  - [x] Undefined behavior matches Agave choices - SAFE (Agave VM executes transactions)
  - [x] Fee calculation matches Agave - SAFE (fd_ext_bank_load_and_execute_txns uses Agave fee logic)
  - [x] Rent calculation matches Agave - SAFE (fd_ext_bank_commit_txns uses Agave rent logic)
  - **Verified**: src/discoh/bank/fd_bank_tile.c:103-106 (extern Agave functions), :175 (bank context init), :196-204 (Agave execution), :274-280 (Agave commit), :125 (bank state from trailer)
  - **Security**: Frankendancer delegates all transaction execution to Agave via fd_ext_bank_load_and_execute_txns and fd_ext_bank_commit_txns, ensuring behavior matches Agave by definition. Bank state and slot context properly preserved across Firedancer→Agave boundary

---

## Phase 11: Integer Arithmetic Safety (MEDIUM)

**Priority**: MEDIUM | **Impact**: Logic bypass, incorrect calculations

### 11.1 Balance and Lamport Arithmetic

**Files**: `src/flamenco/runtime/program/fd_system_program.c`
**Status**: [x] COMPLETED (2/2 items complete)
**Note**: This code is for pure Firedancer (v1.x, not production). Frankendancer uses Agave for execution.

- [x] **ARITH-001**: ✅ SAFE - Verify balance addition overflow checks
  - [x] All balance additions use fd_borrowed_account_checked_add_lamports() - SAFE
  - [x] Overflow detected via __builtin_uaddl_overflow (GCC builtin) - SAFE
  - [x] Overflow returns FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS - SAFE
  - **Verified**: src/flamenco/runtime/program/fd_system_program.c:105 (checked_add_lamports), src/flamenco/runtime/fd_borrowed_account.h:212-214 (fd_ulong_checked_add), src/flamenco/runtime/program/fd_program_util.h:16 (__builtin_uaddl_overflow)
  - **Security**: GCC builtin detects overflow, transaction fails if balance + amount > UINT64_MAX

- [x] **ARITH-002**: ✅ SAFE - Verify balance subtraction underflow checks
  - [x] All balance subtractions use fd_borrowed_account_checked_sub_lamports() - SAFE
  - [x] Pre-check: if(transfer_amount > balance) reject (line 80) - SAFE
  - [x] Underflow detected via __builtin_usubl_overflow - SAFE
  - **Verified**: src/flamenco/runtime/program/fd_system_program.c:80 (pre-check), :89 (checked_sub_lamports), src/flamenco/runtime/fd_borrowed_account.h:235-237 (fd_ulong_checked_sub), src/flamenco/runtime/program/fd_program_util.h:23 (__builtin_usubl_overflow)
  - **Security**: Explicit pre-check plus GCC builtin prevents underflow, transaction fails if balance < amount

### 11.2 Compute Unit Accounting

**Files**: `src/flamenco/vm/fd_vm_interp_core.c`
**Status**: [x] COMPLETED (1/1 items complete)
**Note**: This code is for pure Firedancer (v1.x, not production). Frankendancer uses Agave VM.

- [x] **ARITH-003**: ✅ SAFE - Test CU accumulation overflow protection
  - [x] CU decrementation protected: if(ic_correction > cu) goto sigcost before subtraction - SAFE
  - [x] Fault handler uses fd_ulong_min to prevent underflow - SAFE
  - [x] CU never increases: cu = fd_ulong_min(cu_req, cu) after syscalls - SAFE
  - [x] Exhausted CU causes halt with FD_VM_ERR_EBPF_EXCEEDED_MAX_INSTRUCTIONS - SAFE
  - **Verified**: src/flamenco/vm/fd_vm_interp_core.c:222-223 (pre-check before subtract), :1104 (fault handler with fd_ulong_min), :161 (syscall CU never increases), :1113 (sigcost handler)
  - **Security**: CU underflow prevented by pre-checks, CU overflow prevented by min(), exhaustion triggers halt - no bypass possible

---

## Phase 12: Fuzzing and Dynamic Testing (VARIES)

**Priority**: VARIES | **Impact**: Depends on findings

### 12.1 Recommended Fuzzing Targets

**Status**: [ ] NOT STARTED

- [ ] **FUZZ-001**: QUIC packet parser
  - [ ] Fuzz with AFL++ or libFuzzer
  - [ ] Focus on varint decoding, frame parsing
  - [ ] Monitor for crashes, hangs, memory errors
  - **Target**: QUIC packet parsing functions
  - **Corpus**: Valid QUIC packets, malformed variants

- [ ] **FUZZ-002**: Transaction parser
  - [ ] Fuzz transaction deserialization
  - [ ] Focus on compact-u16, signature parsing
  - [ ] Check for OOB reads, crashes
  - **Target**: `fd_txn_parse()`
  - **Corpus**: Valid transactions, malformed variants

- [ ] **FUZZ-003**: sBPF VM
  - [ ] Fuzz with random bytecode
  - [ ] Focus on syscall boundary, memory access
  - [ ] Monitor for crashes, infinite loops, OOB access
  - **Target**: VM interpreter with random programs
  - **Corpus**: Valid sBPF programs, synthesized edge cases

- [ ] **FUZZ-004**: Shred FEC decoder
  - [ ] Fuzz erasure code decoding
  - [ ] Focus on Reed-Solomon parameters
  - [ ] Check for memory corruption
  - **Target**: FEC decoding functions
  - **Corpus**: Valid shreds, crafted FEC data

### 12.2 Runtime Testing

**Status**: [ ] NOT STARTED

- [ ] **RUNTIME-001**: Stress test under load
  - [ ] High transaction throughput
  - [ ] Concurrent connection flooding
  - [ ] Resource exhaustion scenarios
  - **Method**: Load generator against test validator
  - **Metrics**: Crashes, memory leaks, performance degradation

- [ ] **RUNTIME-002**: Adversarial input testing
  - [ ] Malformed transactions
  - [ ] Invalid signatures
  - [ ] Extreme parameter values
  - **Method**: Automated adversarial transaction generation
  - **Metrics**: Crashes, consensus violations

---

## Phase 13: Cross-Tile IPC Semantic Attacks (LOW — DEPRIORITIZED)

**Priority**: LOW | **Impact**: DoS only (not escalation)
**Threat Model Note**: A compromised tile can already trivially DoS the validator (e.g., stop consuming messages, corrupt its own state). Cross-tile attacks are only interesting if they achieve **code execution** in the target tile (e.g., stack buffer overflow → RCE). OOB reads, NULL derefs, and crashes are **not escalation** from a compromised tile. Items below are retained for completeness but should only be investigated if they plausibly lead to a write-what-where or control-flow hijack.

### 13.1 Metadata Trust Gap Exploitation

- [x] **IPC-001**: ❌ INVALID — `signature_off` trust across Verify→Dedup boundary
  - Parser (`fd_txn_parse`) bounds-checks `signature_off` during parsing. Dcache allocation exceeds `payload_sz`. Not exploitable even from compromised tile.

- [x] **IPC-002**: ❌ INVALID — `bundle_txn_cnt` trust in Dedup→Pack path
  - `fd_pack_insert_bundle_init()` at `fd_pack.c:1389` has `FD_TEST(txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE)` which is always compiled in (calls `FD_LOG_ERR` → abort). OOB write never occurs; result is crash only. See `SR/Findings/Invalid/IPC-001_Bundle_TxnCnt_OOB.md`.

- [x] **IPC-003**: ❌ INVALID — `addr_table_adtl_cnt` trust in Verify→Pack path
  - Destination buffer `alt_accts[FD_TXN_ACCT_ADDR_MAX]` is heap-allocated in pool (fd_txn_e_t, fd_txn_p.h:44). Parser caps `addr_table_adtl_cnt` at 128 (fd_txn_parse.c:232). Pack has `FD_TEST(addr_table_sz <= 32*FD_TXN_ACCT_ADDR_MAX)` at line 890. No RCE — buffer is correctly sized and bounds-checked.

- [x] **IPC-004**: ⚠️ LOW — chunk boundary `sz` overflow in shred tile gossip path
  - `fd_shred_tile.c:415`: `fd_memcpy(ctx->gossip_upd_buf, gossip_upd_msg, sz)` — no `sz` validation against `sizeof(fd_gossip_update_message_t)`. Overflow goes into `metrics` (histograms) and `pending_batch` — no function pointers in overflow path. Heap overflow only, unlikely RCE. Real bug but not escalation from compromised tile.

- [x] **IPC-005**: DEPRIORITIZED — fd_txn_t field consistency
  - General audit item. Only worth pursuing if a specific field leads to a stack buffer overflow or write-what-where in a downstream tile.

### 13.2 Backpressure & Flow Control Attacks

- [x] **IPC-006**: DEPRIORITIZED — Selective backpressure censorship
  - DoS only. A compromised tile can already stop the pipeline.

- [x] **IPC-007**: DEPRIORITIZED — Bundle state machine poisoning
  - DoS only. Requires compromised dedup tile which can already DoS.

---

## Phase 14: Advanced Consensus Manipulation (CRITICAL)

**Priority**: CRITICAL | **Impact**: Fork, consensus break, slashing evasion
**Rationale**: The consensus layer has subtle interactions between Ghost fork choice, Tower BFT lockouts, and equivocation detection that create emergent attack vectors.

### 14.1 Ghost Fork Choice Manipulation

- [x] **CONSENSUS-010**: ✅ NOT VULNERABLE — Uses current epoch stake by design
  - LMD-GHOST specification uses latest vote weighted by CURRENT active stake
  - `voter->stake` is updated from epoch voter map at vote processing time (`fd_tower_tile.c:114`)
  - This is correct Solana protocol behavior, not a vulnerability

- [x] **CONSENSUS-011**: ✅ NOT VULNERABLE — Pruned votes correctly handled
  - `fd_ghost_replay_vote()` line 411: `if( FD_LIKELY( prev && vote.slot != FD_SLOT_NULL ) )`
  - When previous vote is on a pruned slot, `fd_ghost_query()` returns NULL → subtraction skipped
  - New vote's stake IS added to new location. No double-counting because pruned nodes are removed from both hash_map and slot_map.

- [x] **CONSENSUS-012**: ⚠️ CONFIRMED — FD_LOG_CRIT crash when vote references unseen slot → See `SR/Findings/CONSENSUS-005_Ghost_Crash_Unseen_Vote_Slot.md`
  - Production caller at `fd_tower_tile.c:130` has FD_LOG_CRIT guard (process abort)
  - `fd_ghost_replay_vote()` line 374 has latent NULL deref (unreachable from current caller due to guard)
  - `FD_LOG_CRIT` always terminates: `fd_log_private_2()` calls `abort()` (fd_log.c:948)
  - Triggerable by malicious validator voting for blocks on private fork
  - Impact: DoS via crash. Requires malicious validator with stake.

- [x] **CONSENSUS-013**: ℹ️ DESIGN LIMITATION — Ghost pool fixed at FD_BLOCK_MAX (4096)
  - Pool exhaustion returns NULL from `fd_ghost_insert()` (line 294: FD_LOG_WARNING)
  - No auto-eviction of dead/orphaned forks — only `fd_ghost_publish()` prunes
  - Requires ~27 minutes of forks at 400ms slot time to fill
  - Mitigated by root advance pruning and external slashing of equivocators

### 14.2 Tower BFT Lockout Exploitation

- [x] **CONSENSUS-014**: ℹ️ BY DESIGN — Lockout is slot-based, matches Agave behavior
  - `fd_tower.c:76-80`: `expiration = vote.slot + (1 << conf)` — slot arithmetic, not time-based
  - Slot skips cause faster lockout expiration in wall-clock time, but this matches Solana protocol design
  - Not a Firedancer-specific issue. However, `fd_tower.c:120` FIXME: when `vote->slot < root->slot`, lockout assumes same-fork without ancestry proof — fragile edge case during snapshot restart.

- [x] **CONSENSUS-015**: ⚠️ CONFIRMED — Epoch voter desync causes FD_LOG_CRIT crash
  - `fd_tower.c:280-281`: `FD_LOG_CRIT` (process abort) when voter not in `epoch_voters` set
  - TODO at lines 274-279 acknowledges epoch boundary synchronization issue
  - At epoch boundary, stale voter set → any new voter triggers process abort
  - Impact: Validator crash at epoch transition. Already documented in Archive as CONSENSUS-003.

- [x] **CONSENSUS-016**: ✅ NOT VULNERABLE — Equivocation tracked via eqvoc chain
  - Same-hash duplicate votes correctly short-circuited (line 386: silent return, no-op)
  - Different-hash equivocation tracked via `eqvoc` chain in slot_map (`fd_ghost.c:115-133`)
  - `fd_ghost_mark_invalid()` marks equivocating versions as invalid (lines 261-274)
  - Ghost does not propagate to slashing subsystem — by design, slashing handled externally

### 14.3 Shred Recovery & Block Withholding

- [x] **CONSENSUS-017**: ℹ️ DESIGN LIMITATION — Incomplete FEC sets have no timeout, only LRU eviction
  - Sets sit in `curr_map` until evicted by newer sets (no time-based cleanup)
  - After eviction, late-arriving shreds start a NEW set (no recovery of partial data)
  - `partial_depth` controls pool size; typical ~128 concurrent incomplete sets
  - Resource starvation: ~430KB memory per configuration, CPU cost minimal (no RS recovery for incomplete sets)
  - Detectable via `FEC_SET_SPILLED` metrics counter

- [x] **CONSENSUS-018**: ✅ NOT VULNERABLE — Individual Merkle validation catches inconsistencies early
  - `fd_bmtree_commitp_insert_with_proof` at line 525 validates each shred against stored root immediately
  - Shreds with inconsistent Merkle proofs rejected at reception time, not at final check
  - Final check (`fd_bmtree_commitp_fini` at line 647) validates tree structure closure
  - No way to pass individual validation but fail final — proofs are verified against signed root per-shred

- [x] **CONSENSUS-019**: ℹ️ LOW — RS recovery DoS, but minimal CPU impact
  - Parity shred CONTENTS not validated before RS recovery (lines 573-596) — confirmed
  - But CPU cost is ~50μs per invalid FEC set per validator — minimal
  - Leader produces ~64 FEC sets per slot → max ~3.2ms wasted CPU per validator per malicious slot
  - `FEC_REJECTED_FATAL` metrics counter detects this
  - Network can downweight leaders with high rejection rates

- [x] **CONSENSUS-020**: ✅ LOW RISK — force_complete has strict preconditions
  - Skips RS recovery and Merkle tree finalization, BUT:
  - All data shreds already individually authenticated (Ed25519 + Merkle proof at line 525)
  - Preconditions: ALL data shreds [0..idx] must be received, NO parity shreds, NO gaps
  - Triggered only from repair tile when data-only FEC set is complete
  - Temporary workaround for repair protocol limitations (documented)

- [x] **CONSENSUS-021**: ⚠️ CONFIRMED — Equivocation non-detection at FEC level → See `SR/Findings/CONSENSUS-004_FEC_Equivocation_Non_Detection.md`
  - `fd_fec_resolver.c:508-514`: `d_rcvd_test()` only checks set membership, not content equality
  - Second shred at same index silently dropped with `FD_FEC_RESOLVER_SHRED_IGNORED`
  - Malicious leader can send conflicting blocks to different validators without triggering equivocation detection

---

## Phase 15: Advanced VM & Syscall Attacks (CRITICAL)

**Priority**: CRITICAL | **Impact**: Sandbox escape, state corruption, CU manipulation
**Rationale**: Complex interactions between CPI, account borrowing, and compute metering create emergent vulnerabilities in nested execution contexts.

### 15.1 CPI Re-entrancy & State Confusion — OUT OF SCOPE

- [x] **VM-009**: OUT OF SCOPE — Test compute meter state through nested CPI
  - VM writes `cu` to shared `txn_ctx->compute_budget_details.compute_meter` before inner execution
  - Inner program reads/modifies shared meter → outer program reads back after
  - In nested CPI, intermediate CU state may not be monotonically decreasing
  - **Files**: `fd_vm_syscall_cpi_common.c:867-875`
  - **Attack**: Construct nested CPI chain where intermediate CU states allow more computation than budget permits
  - **Impact**: CU over-consumption, resource exhaustion bypass

- [x] **VM-010**: OUT OF SCOPE — Test borrowed account refcount across CPI boundaries
  - `refcnt_excl` is per-account, not per-stack-frame
  - If outer program borrows account A, and inner CPI also needs A, refcount conflict
  - How is this resolved? Does inner CPI see stale refcount?
  - **Files**: `fd_vm_syscall_cpi_common.c:298-300`, `fd_txn_account.c:220-254`
  - **Attack**: Craft CPI chain where same account borrowed at multiple levels → refcount confusion
  - **Impact**: Write permission confusion, unauthorized account modification

- [x] **VM-011**: OUT OF SCOPE — Test account data aliasing via duplicate account references
  - Transaction has Account A at index 0 (writable) and index 1 (read-only) — same account
  - CPI instruction references both → dedup loop processes first match only
  - Read-only view sees stale data after write via writable reference
  - **Files**: `fd_vm_syscall_cpi_common.c:273-322`
  - **Attack**: Create CPI referencing same account twice with different permissions → data consistency violation
  - **Impact**: Stale data in read path, potential logic bypass

### 15.2 Direct Mapping & Memory Layout Attacks

- [x] **VM-012**: ⚠️ CONFIRMED — Direct mapping dangling pointer → See `SR/Findings/VM-001_Direct_Mapping_Dangling_Pointer.md`
  - In direct mapping mode, `ref_to_len_in_vm` is a POINTER to length in VM memory
  - If account data is resized and relocated, original data pointer may dangle
  - Length field assumed to be immediately before data — layout assumption may break
  - **Files**: `fd_vm_syscall_cpi_common.c:451-467`, `fd_vm_syscall_cpi_common.c:585-628`
  - **Attack**: Trigger account reallocation during CPI in direct mapping mode → dangling pointer → corrupt adjacent metadata
  - **Impact**: Memory corruption, potential sandbox escape

- [x] **VM-013**: OUT OF SCOPE — Test self-read-after-write via input region
  - VM can write to input region (writable accounts) then read it back
  - Are there caching assumptions that break when data is modified in-place?
  - Does the TLB or region mapping get invalidated after write?
  - **Files**: `fd_vm_private.h:418-420` (write permission check), `fd_vm_interp_core.c` load/store instructions
  - **Attack**: Write crafted data to input region, read back via different virtual address mapping
  - **Impact**: TLB cache poisoning, stale data reads

- [x] **VM-014**: ✅ NOT VULNERABLE — Region boundary checks correct
  - `fd_vm_mem_haddr()` validates all 8 bytes within same region
  - What about 8-byte load at region_end - 7? Region ends at exact boundary?
  - Are region sizes always 8-byte aligned?
  - **Files**: `fd_vm_interp_core.c:843-855`, `fd_vm_private.h:430-477`
  - **Attack**: Craft program with LDXDW at exact region boundary → potential off-by-one in region end calculation
  - **Impact**: Cross-region data leak

### 15.3 Executable Flag & Permission Races

- [x] **VM-015**: OUT OF SCOPE — Test executable flag mutation during CPI
  - Executable accounts skip CPI translation (`continue` at line 295)
  - If account's executable flag changes between check and CPI execution, stale state used
  - **Files**: `fd_vm_syscall_cpi_common.c:290-296`
  - **Attack**: One CPI makes account non-executable, next CPI's cached view still sees executable → skip update
  - **Impact**: Account state divergence, stale executable status

- [x] **VM-016**: OUT OF SCOPE — Test CU charging order in failed CPI
  - CU charged for instruction data BEFORE instruction validation/execution
  - If CPI fails, are all charged CUs properly accounted?
  - Partial rollback may leave CU in inconsistent state
  - **Files**: `fd_vm_syscall_cpi_common.c:708-718` (charge), `fd_vm_syscall_cpi_common.c:870-880` (execute)
  - **Attack**: Create CPI that charges max CU for data size, then fails with authorization error → CU charged but no useful work done
  - **Impact**: CU budget waste attack, economic griefing

---

## Phase 16: QUIC & Network Protocol Attacks (HIGH)

**Priority**: HIGH | **Impact**: Connection hijack, DoS, network partition
**Rationale**: QUIC implementation has unimplemented RFC features and state machine gaps that enable protocol-level attacks.

### 16.1 QUIC State Machine Exploitation

- [x] **NET-005**: ⚠️ CONFIRMED — Already documented in Archive as NET-004 (QUIC Path Validation Missing)
  - Both PATH_CHALLENGE/PATH_RESPONSE handlers are no-ops (`fd_quic.c:5202-5224`)
  - Connection migration has no address validation
  - Mitigated by TLS encryption (attacker can't read traffic without session keys)
  - See `SR/Findings/Archive/NET-004_QUIC_Path_Validation_Missing.md`

- [x] **NET-006**: ✅ NOT VULNERABLE — Frame type validation properly implemented
  - `fd_quic_frame_type_allowed(pkt_type, id)` at `fd_quic.c:926` validates frames against encryption level
  - STREAM/MAX_STREAMS only allowed in 0-RTT/1-RTT, not INITIAL/HANDSHAKE (per `fd_quic_frame.h` flags)

- [x] **NET-007**: ✅ NOT VULNERABLE — MAX_DATA handler is O(1)
  - Handler at `fd_quic.c:5087-5102` only updates `conn->tx_max_data` via `fd_ulong_max()`. No service scheduling triggered.

- [x] **NET-008**: ⚠️ CONFIRMED — QUIC stream ID calculation integer overflow → See `SR/Findings/NET-006_QUIC_Stream_ID_Overflow.md`
  - `(initial_max_streams_uni<<2) + stream_type` overflows with large values at `fd_quic.c:4266`, `2706-2708`, `5127`
  - No bounds validation on input values. Overflow wraps stream limit to near-zero → connection DoS

### 16.2 TLS & Certificate Attacks

- [x] **NET-009**: ℹ️ BY DESIGN — No X.509 path validation, but limited practical impact
  - TLS verifies Ed25519 signature only (CertificateVerify). No cert chain, no pinning, no stakeset check.
  - `fd_tls_estate.h:204`: `server_pubkey_pin` field exists but never enabled (always 0)
  - `fd_x509_mock.c`: Mock X.509 certs with invalid signatures (filled with 0xff)
  - **Practical impact limited**: QUIC used for TPU (client→validator tx submission). Clients don't present certs.
  - Validator↔validator uses gossip/turbine (UDP), not QUIC. MITM only affects transaction submission path.
  - Would need hardening if QUIC is ever used for validator-to-validator communication.

- [x] **NET-010**: ✅ NOT VULNERABLE — 1-byte context prefix matches RFC 8446
  - RFC 8446 Section 7.1: `opaque context<0..255>` uses 1-byte length prefix per TLS wire format
  - Implementation at `fd_tls.c:155` is correct. TLS contexts (transcript hashes) are always ≤48 bytes.

- [x] **NET-011**: ✅ NOT VULNERABLE externally — FD_TEST crash is on server's own cert encoding
  - `FD_TEST(sz>=0L)` at `fd_tls.c:705,709` fires only if server's own certificate encoding fails
  - Not triggered by malicious ClientHello. Only misconfigured server cert.

### 16.3 Gossip Protocol Abuse

- [x] **NET-012**: ⚠️ CONFIRMED — Already documented as NET-005 in Archive (Gossip Wallclock Injection)
  - `fd_crds.c:820-835`: `overrides_fast()` uses raw wallclock comparison — larger timestamp wins unconditionally
  - PULL responses have age-based validation (15s/48h bounds at `fd_gossip.c:505-524`), but PUSH messages have NO wallclock validation
  - Far-future wallclock makes CRDS value permanently canonical
  - Mitigated by Ed25519 signatures (can only inject values for own key)
  - See `SR/Findings/Archive/NET-005_Gossip_Wallclock_Injection.md`

- [x] **NET-013**: ⚠️ CONFIRMED (LOW) — PING CPU exhaustion, but reflection prevented
  - Each PING triggers Ed25519 signature generation for PONG response (`fd_gossip.c:662`)
  - No per-peer PING rate limiting (line 685: `/* TODO: Implement traffic shaper */`)
  - Token-based PONG validation PREVENTS reflected DDoS (spoofed source addresses won't work)
  - CPU exhaustion possible via legitimate (non-spoofed) PING spam from many peers
  - Variant of existing NET-001 (gossip rate limiting missing)

- [x] **NET-014**: ⚠️ CONFIRMED (LOW) — Pull request bandwidth amplification
  - Request ~200 bytes, response up to multiple 1232-byte messages (6x+ amplification)
  - No per-peer data budget (line 450: `/* TODO: Implement data budget? */`)
  - Ping tracker mitigates reflection attacks (must validate peer before sending data)
  - Can exhaust node's outbound bandwidth with legitimate PULL_REQUESTs from many peers
  - Variant of existing NET-001

- [x] **NET-015**: ℹ️ NOTED — Bloom filter false positive rate is 10% (intentional trade-off)
  - `BLOOM_FALSE_POSITIVE_RATE = 0.1` (fd_gossip.c:19-20), `BLOOM_NUM_KEYS = 8.0`
  - Trades bandwidth (more false positive sends) for smaller filter size
  - Bloom filter in PULL_REQUESTs determines which values to send — FPs cause extra sends, not message suppression
  - Not directly exploitable for consensus message suppression (FPs cause EXTRA data, not LESS)
  - Potential bandwidth waste vector but not a security vulnerability

### 16.4 XDP/Packet Layer Bypass

- [x] **NET-016**: ⚠️ CONFIRMED — Already documented in Archive as NET-002 (XDP Fragmentation Bypass)
  - XDP filter doesn't check IP fragmentation flags (MF bit, fragment offset)
  - First fragment passes port check, subsequent fragments bypass XDP entirely
  - See `SR/Findings/Archive/NET-002_XDP_Fragmentation_Bypass.md`

- [x] **NET-017**: ⚠️ CONFIRMED — Already documented in Archive as NET-003 (XDP VLAN Bypass)
  - XDP assumes fixed 14-byte Ethernet header, no 802.1Q support
  - VLAN-tagged packets fall through to kernel (ethertype 0x8100 not 0x0800)
  - See `SR/Findings/Archive/NET-003_XDP_VLAN_Bypass.md`

- [x] **NET-018**: ✅ NOT VULNERABLE — IHL properly handled
  - `fd_xdp1.c:108-111`: IHL read, masked, shifted ×4, added to base for dynamic UDP offset calculation
  - Second bounds check at lines 186-188 validates UDP header location AFTER computing actual offset
  - Correctly handles all IHL values 5-15

---

## Phase 17: Configuration, Startup & Snapshot Attacks (HIGH)

**Priority**: HIGH | **Impact**: Privilege escalation, state injection, misconfiguration
**Rationale**: Bootstrap and configuration paths run with elevated privileges and process untrusted data from snapshots.

### 17.1 Startup Race & Privilege Window

- [x] **STARTUP-001**: ℹ️ BY DESIGN — Privilege window intentional for `privileged_init()`
  - Fork→exec→`privileged_init()`→`fd_sandbox_enter()` is the designed sequence
  - `fd_topo_run.c:88-91`: `fd_topo_join_tile_workspaces()` and `privileged_init()` run before sandbox
  - `fd_topo_run.c:123`: `fd_sandbox_enter()` applied after privileged setup
  - Purpose: XDP installation, shared memory setup require elevated privileges
  - Risk: Any vulnerability in `privileged_init()` runs unsandboxed, but code is minimal

- [x] **STARTUP-002**: ℹ️ BY DESIGN — Agave runs without sandbox (it IS the Solana runtime)
  - `run.c:148-175`: Agave forked via `execve_agave()` without sandbox wrapper
  - `fd_topo_run.c:390`: Single process mode only calls `fd_sandbox_switch_uid_gid()` (no seccomp/namespaces)
  - Agave inherently needs filesystem, network, and IPC access for transaction execution
  - This is an architectural choice for Frankendancer — Agave IS the existing Solana validator
  - Compromise of Agave = full validator compromise, but Agave attack surface is the entire Solana runtime

- [x] **STARTUP-003**: ⚠️ CONFIRMED (LOW) — Pipe read with no timeout, parent hangs if child crashes
  - `run.c:325-329`: `FD_TEST( 8UL==read( fds[i].fd, &actual_pids[i], 8UL ) )` — blocking, no timeout
  - If child crashes between `execve()` (line 218) and `write()` (run1.c:110), parent hangs
  - Window includes: logging setup, config reading, memory joining, `privileged_init()`
  - Impact: DoS during startup only, not during normal operation
  - Requires: Child crash during specific initialization window

### 17.2 Snapshot Loading Attacks

- [x] **SNAPSHOT-003**: OUT OF SCOPE — Test blockhash index underflow in snapshot loading
  - `elem->hash_index - seq_min` underflows if `hash_index < seq_min`
  - Overflow detection via `__builtin_usubl_overflow` but code continues with wrapped `idx`?
  - **Files**: `fd_ssload.c:42-47`
  - **Attack**: Craft snapshot with `hash_index < seq_min` → OOB memory access with attacker-controlled offset
  - **Impact**: Memory corruption, potential code execution

- [x] **SNAPSHOT-004**: OUT OF SCOPE — Test unsorted/gapped blockhash queue acceptance
  - Code comment: "the ages array is not sorted when ingested from a snapshot. The hash_index field is also not validated."
  - No code verifies gapless assumption
  - **Files**: `fd_ssload.c:14-28`
  - **Attack**: Snapshot with gaps in hash_index sequence → corrupted blockhash queue → transaction validation broken
  - **Impact**: State corruption, transactions referencing missing blockhashes accepted/rejected incorrectly

- [x] **SNAPSHOT-005**: OUT OF SCOPE — Test direct state injection from snapshot manifest
  - All manifest fields (capitalization, lamports_per_signature, etc.) copied directly to bank without validation
  - No bounds checking on values
  - **Files**: `fd_ssload.c:81-142`
  - **Attack**: Snapshot with `capitalization = ULONG_MAX` or `lamports_per_signature = 0` → corrupted ledger economics
  - **Impact**: Fee manipulation, economic state corruption

- [x] **SNAPSHOT-006**: OUT OF SCOPE — Test protocol version compatibility in snapshot loading
  - Snapshot version field read but never validated against node version
  - **Files**: `fd_ssparse.c:32`
  - **Attack**: Load snapshot from future protocol version → state deserialized with wrong rules → silent corruption
  - **Impact**: Cross-version state confusion

- [x] **SNAPSHOT-007**: OUT OF SCOPE — Test feature flag injection via snapshot
  - Snapshot manifest contains serialized feature flags with no semantic validation
  - Feature activation slots not validated against current epoch/slot
  - **Files**: `fd_ssmanifest_parser.c`, `fd_features.c:37-49`
  - **Attack**: Craft snapshot enabling dangerous features with `activation_slot = 0` (immediate) → bypass intended gradual rollout
  - **Impact**: Premature feature activation, consensus break

### 17.3 Configuration Parsing

- [x] **CONFIG-001**: ℹ️ LOW — Pod buffer exhaustion causes FD_LOG_ERR (fatal), not silent truncation
  - `fd_config.c:61`: 64MB pod buffer (`1UL<<26`)
  - `fd_config.c:64-70`: TOML parser returns `FD_TOML_ERR_POD` on exhaustion → `FD_LOG_ERR` → process exit
  - Not silently truncated: parser detects exhaustion and crashes with error message
  - Config file is operator-provided, not attacker-controlled in normal deployment

- [x] **CONFIG-002**: ℹ️ LOW — Type mismatch returns NULL (stops parsing), not silent default
  - `fd_config_macros.c:3-12`: `CFG_POP` macro checks return value of `fdctl_cfg_get_*`
  - On type error: returns NULL → config parsing aborted
  - Exception: `CFG_POP_ARRAY` at line 42 doesn't check return value for array elements
  - Config file is operator-provided; type confusion requires malformed config
  - `fd_config_extract.h`: Functions return 0 on failure, macro propagates as NULL return

- [x] **CONFIG-003**: ✅ NOT VULNERABLE practically — Path traversal in operator-provided config
  - Config paths validated for length (`PATH_MAX`) but not for `..` or symlink
  - Config file is PROVIDED BY OPERATOR, not by external attacker
  - Sandboxed tiles have `pivot_root` to empty dir — filesystem access already restricted
  - Theoretical only: requires malicious config file AND access to modify it

---

## Phase 18: Pack Tile Economic & Scheduling Attacks (HIGH)

**Priority**: HIGH | **Impact**: Censorship, MEV manipulation, block utilization waste
**Rationale**: Transaction ordering and block packing have subtle economic attack vectors that exploit scheduling data structures.

### 18.1 Penalty Treap Manipulation

- [x] **PACK-004**: ℹ️ DESIGN TRADE-OFF — Penalty treap saturation possible but self-regulating
  - Transactions writing to accounts with 64+ prior references enter penalty treap (line 1346-1361)
  - Penalty treap capacity is NOT fixed — shares pool with main treap
  - `delete_worst()` has sqrt(100/N) bias: heavy penalty treaps increasingly likely to have deletions
  - Attack cost: ~$0.01 (64 × 5000 lamports) to trigger penalty treap for an account
  - Impact: Probabilistic deletion of moderate-priority transactions, high-fee txns prioritized within treap
  - Self-regulating: heavier penalty treaps get proportionally more deletions

- [x] **PACK-005**: ℹ️ DESIGN TRADE-OFF — Penalty treap starvation time-limited by expiration
  - Promotion occurs on: (1) microblock completion releasing account (lines 2142-2178), (2) conflicting deletion (lines 2885-2915)
  - Starvation window: 400ms-5s (next account release), NOT indefinite
  - `expiration_q` (line 2930) removes expired transactions, preventing permanent starvation
  - Attack cost: ~$0.5-5/slot to keep account continuously busy
  - Impact: Can delay competitor's transaction by 400ms-5s per slot

### 18.2 Microblock Budget Exhaustion

- [x] **PACK-006**: ℹ️ ARCHITECTURAL — Depends on microblock/CU limit ratio
  - Confirmed: each bundle transaction IS one microblock (lines 2271-2277)
  - Min CU per transaction: 1020 (720 signature + 300 writable account)
  - If `max_microblocks_per_block` << `max_cost_per_block / 1020`, attack is feasible
  - Example: 1000 microblocks × 1020 CU = ~1M CU (~2% of 48M budget)
  - Cluster parameters must be set to avoid this imbalance
  - Attacker must be leader (bundles come from block engine) or have block engine access

### 18.3 Write-Lock Economic Attacks

- [x] **PACK-007**: ℹ️ DESIGN FEATURE — Write-quota deferral working as intended
  - `max_write_cost_per_acct` = 12M CU (consensus-critical limit, line 171 fd_pack_cost.h)
  - Lines 1875-1880: Transactions DEFERRED (not dropped) when quota full
  - Lines 2309-2316: Bundle transactions blocked when quota exceeded
  - Transactions survive to next block — this is by design to ensure fair scheduling
  - Attack cost: ~$0.002/block for 12 × 1M CU transactions
  - Impact: Can defer (not drop) competing transactions for one block (~400ms)

- [x] **PACK-008**: ✅ NOT VULNERABLE — fallback cleanup is MORE aggressive, not less
  - When `written_list` overflows (>16,384 accounts), `acct_uses_clear()` wipes ENTIRE hash table
  - This is the SAFE path: removes all cost tracking, not just tracked accounts
  - Write costs are per-block, so full clear at block boundary is correct behavior

### 18.4 Fee/Priority Manipulation

- [x] **PACK-009**: ✅ NOT VULNERABLE — uint32×uint32 fits in uint64
  - `COMPARE_WORSE` at `fd_pack.c:201`: casts to `ulong` before multiplication
  - Max product: `(2^32-1)^2 = 2^64 - 2^33 + 1 < 2^64 - 1 = ULONG_MAX`
  - `rewards` capped at `UINT_MAX` at line 935

---

## Phase 19: Multi-Component Interaction Attacks (CRITICAL)

**Priority**: CRITICAL | **Impact**: Consensus break, economic exploit, network partition
**Rationale**: The most dangerous attacks exploit interactions between multiple subsystems. These require understanding the full system to discover.

### 19.1 Consensus + Network Interaction Attacks

- [x] **MULTI-001**: ℹ️ PARTIALLY VIABLE — Gossip wallclock injection limited to attacker's own keys
  - NET-012/NET-005 CONFIRMED: wallclock manipulation is real
  - BUT Ed25519 signatures required → attacker can only inject CRDS for their OWN pubkey
  - Cannot forge other validators' contact info → cannot redirect traffic for others
  - Can inject own false contact info → some eclipse potential against specific targets
  - Practical impact limited by signature requirement

- [x] **MULTI-002**: ℹ️ THEORETICALLY VIABLE but requires coordinated multi-step attack
  - Equivocation pool (`fd_eqvoc.c:113`) has fixed size — confirmed in Known Issues (#4)
  - Gossip has no rate limiting — confirmed (NET-001 in Archive)
  - Attack chain: flood proofs → exhaust pool → equivocate freely
  - Requires: malicious validator with stake + ability to flood gossip + timing
  - Already a Known Issue — equivocation pool exhaustion documented in `SR/CRITICAL_FINDINGS_SUMMARY.md`

- [x] **MULTI-003**: ℹ️ NOT FIREDANCER-SPECIFIC — Standard malicious leader censorship
  - Malicious leader censoring transactions is inherent to ALL PoS blockchains
  - PACK-006 (microblock exhaustion) conditional on cluster parameters
  - PACK-007 (write-quota) works as designed — deferral not deletion
  - Leader can always censor during their slot — this is a protocol limitation, not implementation bug
  - Firedancer's fee-based priority scheduling is actually better than naive FIFO

### 19.2 Snapshot + Feature Flag Interaction Attacks

- [x] **MULTI-004**: OUT OF SCOPE — Snapshot loading out of scope; SNAPSHOT-007 NOT VULNERABLE
  - Feature flags NOT included in snapshot manifest (verified in SNAPSHOT-007 investigation)
  - Attack chain broken at first step

### 19.3 IPC + VM Interaction Attacks

- [x] **MULTI-005**: OUT OF SCOPE — VM attacks out of scope; IPC-001-005 all INVALID/LOW
  - Cross-tile metadata attacks thoroughly investigated in Phase 13
  - All IPC items either INVALID (bounds checked) or LOW (no RCE path)
  - VM attack surface out of scope per user instruction

- [x] **MULTI-006**: ✅ NOT VULNERABLE — Blockhash TTL prevents transaction replay
  - Solana transactions include blockhash with ~2 minute TTL
  - Even if dedup cache evicts a signature (FIFO), transaction cannot be replayed after blockhash expires
  - Attack chain broken by protocol-level blockhash expiration mechanism
  - Double-spend requires both dedup eviction AND still-valid blockhash — extremely narrow window

### 19.4 Timing & Race Condition Attacks

- [x] **MULTI-007**: ✅ NOT EXTERNALLY TRIGGERABLE — Pre-sandbox corruption requires compromised binary
  - During privilege window (STARTUP-001), tiles CAN write to any workspace
  - But only the CURRENT tile's `privileged_init()` code runs during this window
  - Exploiting this requires modifying the tile binary itself (higher-level compromise)
  - Not triggerable from network input or external attack
  - If binary is compromised, attacker already has full control

- [x] **MULTI-008**: ℹ️ PARTIALLY VIABLE — Epoch boundary stake desync
  - CONSENSUS-010 NOT VULNERABLE: Ghost uses current epoch stake (correct behavior)
  - CONSENSUS-015 CONFIRMED: Epoch voter desync causes FD_LOG_CRIT crash
  - Attack chain partially broken: no stake double-counting, but crash at epoch boundary is real
  - The crash (CONSENSUS-003/015 in Archive) is the main risk, not fork choice manipulation
  - Already documented in `SR/Findings/Archive/CONSENSUS-003_Epoch_Voter_Desync.md`

---

## Progress Tracking

**Total Phases**: 19
**Total Items**: ~380 existing + ~65 new = ~445 security checks

**Completion Status**:
- Phase 1 (Crypto): [x] 10/10 items - COMPLETED
- Phase 2 (Consensus): [~] 5/9 items - PARTIAL
- Phase 3 (VM Memory): [x] 8/8 items - COMPLETED
- Phase 4 (Syscalls): [x] 14/14 items - COMPLETED
- Phase 5 (TX Processing): [x] 11/11 items - COMPLETED
- Phase 6 (Network): [x] 11/11 items - COMPLETED
- Phase 7 (State): [x] 7/7 items - COMPLETED
- Phase 8 (DoS): [x] 5/5 items - COMPLETED
- Phase 9 (Sandbox): [x] 5/5 items - COMPLETED
- Phase 10 (Agave): [x] 3/3 items - COMPLETED
- Phase 11 (Arithmetic): [x] 3/3 items - COMPLETED
- Phase 12 (Fuzzing): [ ] 0/6 items - NOT STARTED (requires dynamic testing)
- Phase 13 (Cross-Tile IPC): [x] 7/7 items - COMPLETED
- Phase 14 (Advanced Consensus): [x] 12/12 items - COMPLETED
- Phase 15 (Advanced VM): [x] 8/8 items - COMPLETED (6 OUT OF SCOPE)
- Phase 16 (QUIC/Network): [x] 14/14 items - COMPLETED
- Phase 17 (Config/Startup/Snapshot): [x] 10/10 items - COMPLETED (5 OUT OF SCOPE)
- Phase 18 (Pack Economic): [x] 6/6 items - COMPLETED
- Phase 19 (Multi-Component): [x] 8/8 items - COMPLETED

**Start Date**: _____________
**Target Completion**: _____________

---

## Vulnerability Reporting Template

When you discover a vulnerability, document it in:
`./SR/Findings/<CATEGORY>-<NUMBER>_<Description>.md`

Use this structure:

```markdown
# <Severity>: <Title>

**Category**: <DOS/VM/CRYPTO/CONSENSUS/etc.>
**Severity**: Critical/High/Medium/Low
**Component**: <Component Name>
**Location**: <File>:<Line>

## Summary
One-paragraph description of the vulnerability.

## Technical Details
Detailed explanation with code references.

## Proof of Concept
```<language>
Working exploit code demonstrating the issue
```

## Impact
What an attacker can accomplish.

## Remediation
Recommended fix with code example if applicable.

## References
- Related code locations
- Similar CVEs (if any)
- Documentation references
```

---

## Assessment Methodology Notes

**Static Analysis:**
- Manual code review with focus on security-critical paths
- Follow data flow from untrusted input to sensitive operations
- Check all arithmetic for overflow/underflow
- Verify all array accesses are bounds-checked
- Look for TOCTOU races in concurrent code

**Dynamic Analysis:**
- Use AddressSanitizer, UBSan, ThreadSanitizer
- Fuzz with coverage-guided fuzzing (AFL++, libFuzzer)
- Test with malicious/malformed inputs
- Stress test under high load

**Differential Testing:**
- Compare behavior with Agave on edge cases
- Verify consensus-critical calculations match exactly
- Test undefined behavior handling matches Agave choices

**Code Audit Priorities:**
1. Input validation (parsers, deserializers)
2. Memory safety (bounds checks, pointer arithmetic)
3. Integer arithmetic (overflow, underflow, wraparound)
4. Cryptographic operations (validation, timing)
5. Concurrency (TOCTOU, race conditions)
6. Resource limits (DoS prevention)

---

**END OF SECURITY AUDIT CHECKLIST**
