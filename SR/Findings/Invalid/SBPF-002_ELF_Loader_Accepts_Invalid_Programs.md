# SBPF-002: ELF Loader Accepts Programs Rejected by Agave

**Severity:** Informational (fuzzer asymmetry, not a consensus bug)
**Component:** `src/ballet/sbpf/fuzz_sbpf_loader_diff.c` (test harness)

## Description

Firedancer's sBPF ELF loader (`fd_sbpf_program_load`) accepts ELF binaries that
Agave's `solana-sbpf` `Executable::load + verify` rejects. Found via differential
fuzzing within seconds.

The crash input is a V0 (e_flags=0) ELF of 2848 bytes. The mismatch direction
(`fd=1 agave=0`) means Firedancer's loader considers the program structurally valid
while Agave's combined load+verify pipeline rejects it.

## Root Cause

**Fuzzer harness asymmetry - not a real consensus divergence.**

The ELF contains a `.text` section with two sBPF instructions:
1. `callx r10` (opcode 0x8d, imm=10) - attempts to call via the frame pointer register
2. `exit` (opcode 0x95)

The ELF structure itself is well-formed (valid headers, sections, dynamic table, etc.),
so both Firedancer and Agave's ELF loading step succeeds. The divergence occurs because:

- **Agave harness** tests `Executable::load` AND `RequisiteVerifier::verify`. The verifier
  (`verifier.rs:198-214`) calls `check_callx_register` which checks that the callx target
  register is in range `[0, 10)`. Since `imm=10` (r10, the frame pointer) is not in
  `[0, 10)`, verification fails with `InvalidRegister`.

- **Firedancer harness** tests ONLY `fd_sbpf_elf_peek` + `fd_sbpf_program_load`. It does
  NOT call `fd_vm_validate`, which contains the equivalent check at `fd_vm.c:427-431`
  (`FD_CHECK_CALL_REG_IMM: instr.imm > 9`).

In the production validator, `fd_vm_validate` IS called after loading:
- `fd_bpf_loader_program.c:221` (deployment path)
- `fd_progcache_rec.c:180` (program cache / execution path)

So the full production pipeline (load + validate) correctly rejects this ELF in both
implementations. The divergence is purely a fuzzer coverage gap.

## Recommendations

1. Update `fuzz_sbpf_loader_diff.c` to call `fd_vm_validate` after successful
   `fd_sbpf_program_load`, so the Firedancer harness matches the Agave harness's
   load+verify pipeline. This eliminates false positives from instruction-level
   validation that is intentionally separated from ELF loading in Firedancer.

2. Consider also fuzzing `fd_vm_validate` independently against `RequisiteVerifier::verify`
   with known-valid ELFs to catch any divergences in the instruction validation logic itself
   (e.g., the `FD_CHECK_CALL_REG_IMM` check uses unsigned comparison `instr.imm > 9` while
   Agave uses signed range check `!(0..10).contains(&reg)` - these are equivalent for all
   uint values but the semantic difference merits explicit testing).

## Reproduction

Crash input saved at `SR/Findings/Crashes/sbpf_accepts_invalid_001.bin`. Run:
```
build/native/clang/fuzz-test/fuzz_sbpf_loader_diff SR/Findings/Crashes/sbpf_accepts_invalid_001.bin
```

## Found By

Differential fuzzing: `fuzz_sbpf_loader_diff` (Firedancer fd_sbpf_program_load vs
Agave solana-sbpf Executable::load + RequisiteVerifier::verify)
