# Fuzzer Triage Guide

## Lessons Learned

### 1. Fresh-process replay does NOT reliably reproduce mismatches

libfuzzer's `-runs=1` on a single file executes the input as a corpus entry.
It does NOT exercise the full comparison function the same way the fuzzing loop
does. A mismatch that occurs during fuzzing may appear to "not reproduce" when
replayed this way, even though it is real and deterministic.

**Correct reproduction method:** Use the in-process re-verification built into
the fuzzer. When a mismatch is detected, the fuzzer immediately re-runs the same
input through both sides and classifies it as CONFIRMED or TRANSIENT.

- CONFIRMED: mismatch reproduces on immediate re-run in the same process. This
  is a real, deterministic divergence.
- TRANSIENT: mismatch does not reproduce on re-run. This indicates state leakage
  from prior executions corrupting the result.

### 2. Feature scope filtering is subtle

The protobuf wire format has several pitfalls for scope filtering:

- **Packed encoding:** Proto3 `repeated fixed64` fields use packed encoding
  (field tag 0x0a = wire type 2, not 0x09 = wire type 1).
- **Duplicate submessages:** Protobuf allows a submessage field to appear
  multiple times. The decoder merges all occurrences. A wire-format scanner
  must check ALL occurrences, not just the first.
- **Corrupted protobufs:** Fuzz-mutated protobufs can have corrupted nesting
  where the scanner misidentifies field boundaries. The Python protobuf
  decoder may see different feature IDs than the C wire-format scanner.

**Definitive scope check:** When triaging a mismatch, always use the Python
protobuf decoder (not the C wire scanner) to determine the actual feature set.
The C scanner is a best-effort filter to reduce noise during fuzzing.

### 3. Out-of-scope features cause real divergences

Confirmed: inputs with out-of-scope feature IDs produce deterministic,
reproducible divergences between FD and Agave. These are real implementation
differences but are outside the contest scope (non-mainnet features).

When an OOS feature causes a divergence, removing only that feature and
re-running confirms whether the divergence is feature-dependent. If removing
the OOS features eliminates the divergence, it is not reportable.

### 4. Mismatch direction matters

- `fd_ok=0, agave_ok=1`: FD rejects, Agave accepts. This is the most
  dangerous pattern - Agave would process a transaction that FD skips,
  causing a bank hash divergence.
- `fd_ok=1, agave_ok=0`: FD accepts, Agave rejects. Also dangerous but
  in the opposite direction.
- `fd_ok=1, agave_ok=1, output differs`: Both execute but produce different
  state. Could indicate account balance, CU, or return data differences.

## Triage Checklist for Each Mismatch

1. **Verify reproducibility**: Check CONFIRMED/TRANSIENT status from the
   fuzzer's re-verification log. If TRANSIENT, it's a state leak artifact.

2. **Decode with Python**: Use the protosol protobuf decoder to extract the
   actual feature set. Do NOT rely on the C wire-format scanner alone.

3. **Check feature scope**: Every feature ID in the input must be in the
   in-scope set (215 IDs: 194 cleaned_up + 17 hardcode_for_fuzzing + 4
   scope exceptions). If ANY feature is OOS, test whether removing it
   eliminates the divergence.

4. **Check known issues**: Compare against the excluded known issues listed
   in `SR/Scope.md`:
   - #9170: VM/SBPF/ELF - CPI error handling, log mismatches, .text ordering
   - #9171: Runtime - snapshot hash bypass, stake delegation divergence, etc.
   - #9161: Pack/bank - malicious trailers, OOB writes, lazy CU accounting
   - All issues listed in the table at SR/Scope.md lines 86-108

5. **Determine severity**: Per SR/Scope.md reward structure:
   - Critical: loss of funds, forged signatures, infinite mint
   - High: bank hash mismatch, sandbox escape, accounts DB corruption
   - Medium: invalid block production, leader slot skip, leader crash
   - Low: limited liveness issues

6. **Write PoC**: A runnable proof-of-concept is mandatory for all severity
   levels. The fuzzer mismatch file IS a PoC if it reproduces through the
   sol_compat harness.
