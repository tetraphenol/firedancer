# SBPF-003: ELF Loader Rejects Valid Programs With Out-of-Segment Section Vaddrs

**Severity:** Medium (potential consensus divergence on program deployment/execution)
**Component:** `src/ballet/sbpf/fd_sbpf_loader.c`

## Status - INVALID

The divergence is real but only reachable via optimize_rodata=true, which is Config::default() but
NOT what create_program_runtime_environment_v1 ever produces. And optimize_rodata is hardcoded to
false in production.

This means the bug exists only in a config path that is never used in production or in the solfuzz
harness. It's a Config::default() vs production-config divergence in the test setup.

## Description

Firedancer's sBPF ELF loader rejects ELF binaries where section virtual addresses
fall outside any LOAD program header segment, while Agave's `solana-sbpf`
`Executable::load` accepts them. The mismatch direction is `fd=0 agave=1` -
Firedancer rejects what Agave considers valid.

3 inputs found across 679M executions, all V0 (e_flags=0). All share the same
structural pattern: a `.rodata` or `.text` section whose `sh_addr` lies outside
the virtual address ranges covered by PT_LOAD program headers.

## Root Cause

Firedancer's ELF loader validates that section vaddrs are consistent with LOAD
segment vaddrs. Agave's `solana-sbpf` loader uses LOAD segments to construct
the memory map and doesn't validate that section headers agree with it.

Example (1632-byte input):
- LOAD segments cover vaddr ranges: `0x120-0x14f`, `0x150-0x153`, `0x158-0x207`,
  `0x208-0x27f`
- `.rodata` section claims vaddr `0x662` (outside all LOAD ranges)
- Firedancer rejects; Agave accepts

## Impact Assessment

If a deployed program has an ELF with this structure:
- Agave can load and execute it
- Firedancer refuses to load it
- Any transaction that invokes this program would succeed on Agave but fail on
  Firedancer, causing a bank hash divergence

The practical question is whether the Solana BPF toolchain (llvm/lld) can produce
ELFs with this property. Standard toolchain output has consistent section-to-segment
mappings. However:
- Maliciously crafted ELFs (via raw binary manipulation) could have inconsistent
  mappings
- Future toolchain changes might relax this invariant
- rbpf explicitly handles section/segment divergence by preferring segments

This is distinct from SBPF-002 (harness asymmetry). SBPF-002 is about missing
`fd_vm_validate` in the harness; this finding is about `fd_sbpf_program_load` itself
rejecting structurally valid ELFs.

## Minimal Reproducers

Raw ELF binaries:
- `SR/Findings/Crashes/sbpf_fd_rejects_1632.bin` (1632 bytes, V0)
- `SR/Findings/Crashes/sbpf_fd_rejects_1920.bin` (1920 bytes, V0)

```
build/native/clang/fuzz-test/fuzz_sbpf_loader_diff SR/Findings/Crashes/sbpf_fd_rejects_1632.bin
```

## Solfuzz Harness Input (elf_loader)

A FlatBuffers `ELFLoaderCtx` fixture is available at:
- `SR/Findings/Crashes/sbpf003_elf_loader_ctx.fix` (1692 bytes)

This wraps the 1632-byte crash ELF in the `elf_loader` harness input format
(FlatBuffers `ELFLoaderCtx` with empty feature set and `deploy_checks=false`).
It can be fed to `sol_compat_elf_loader_v2` in `libfd_exec_sol_compat.so` and
the equivalent function in `libsolfuzz_agave.so` to reproduce the divergence:
- Firedancer: returns error (non-zero `err_code`) because `fd_sbpf_program_load`
  rejects the ELF at the section-to-segment validation step
- Agave: returns success with `rodata_hash`, `text_cnt`, `calldests_hash`, etc.

Generator tool: `src/ballet/sbpf/gen_sbpf003_fixture.c`

## E2E Test Result

Tested on LocalNet (Agave 3.1.11 + Firedancer 0.1.1, 2 validators in consensus).

**Deployment transaction was rejected by BOTH validators.** The on-chain BPF
Upgradeable Loader calls `Executable::load` with `reject_broken_elfs=true`
(deployment path), which triggers Agave's section addr/offset consistency check
before reaching the Firedancer-specific `highest_addr > bin_sz` check. Both
sides return `InvalidAccountData`. Firedancer replayed the slot normally, voted
on it, and advanced root. No bank hash divergence.

**The divergence only manifests with `reject_broken_elfs=false`** (the program
execution path, not deployment). This would require a malformed ELF to already
exist on-chain from a historical deployment before the `reject_broken_elfs` checks
were introduced. Whether such programs exist on mainnet is unknown.

PoC script: `SR/PoC/SBPF-003/deploy_crafted_elf.sh` (also `/tmp/deploy_sbpf003.py`
on the test VM, which bypasses CLI-side validation via raw transactions).

## Revised Severity

**Informational.** The library-level divergence is real but not exploitable via
new program deployments. Impact is limited to the theoretical scenario of
pre-existing malformed programs from before the `reject_broken_elfs` era.

## Found By

Differential fuzzing: `fuzz_sbpf_loader_diff`. 3 inputs out of 679M executions (rare).
