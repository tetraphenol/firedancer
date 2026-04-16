# CONSENSUS-002: Equivocation Proof Censorship PoC

## Overview

This proof-of-concept demonstrates the equivocation proof censorship vulnerability (CONSENSUS-002) by showing how a malicious wallclock timestamp can permanently block chunk assembly for duplicate shred proofs.

## Attack Demonstration

The PoC submits three sets of equivocation proof chunks to a local `fddev` node:

1. **Slot 100**: Normal proof submission (will fail validation due to garbage data, but chunks assemble)
2. **Slot 200**: Poisoned proof - malicious chunk sent first with far-future wallclock
3. **Slot 300**: Normal proof submission (will fail validation due to garbage data, but chunks assemble)

**Expected Outcome:**
- Slot 100: Logs show chunk assembly → validation failure
- **Slot 200: NO logs** (chunks never assemble - attack successful!)
- Slot 300: Logs show chunk assembly → validation failure

The absence of validation logs for slot 200 proves that the wallclock poisoning prevented chunk assembly, demonstrating the vulnerability.

## Requirements

- `fddev` running locally with default configuration
- Rust toolchain (for building the PoC)
- Access to `fddev` logs (typically `--log-path` or stdout)

## Building

```bash
cd SR/Findings/PoC/CONSENSUS-002
cargo build --release
```

## Usage

### Step 1: Start fddev with verbose logging

```bash
# Terminal 1: Start fddev with gossip logging enabled
fddev --log-level 3 --log-path ./fddev.log dev
```

### Step 2: Run the PoC

```bash
# Terminal 2: Run the PoC
cd SR/Findings/PoC/CONSENSUS-002
cargo run --release

# Or if built:
./target/release/consensus-002-poc
```

### Step 3: Examine logs

```bash
# Look for chunk processing and validation logs
grep -E "(chunk|duplicate|eqvoc)" fddev.log

# Or use the provided log analyzer:
cargo run --release -- --analyze-logs ./fddev.log
```

## Expected Log Output

### Slot 100 (Normal - Chunks Assemble, Validation Fails)
```
[eqvoc] received chunk (slot: 100, from: FakeValidator..., index: 0/3)
[eqvoc] received chunk (slot: 100, from: FakeValidator..., index: 1/3)
[eqvoc] received chunk (slot: 100, from: FakeValidator..., index: 2/3)
[eqvoc] proof complete for slot 100, verifying...
[ERROR] proof verification failed: invalid signature
```

### Slot 200 (Poisoned - NO Assembly, NO Validation)
```
[eqvoc] received chunk (slot: 200, from: FakeValidator..., index: 0/3) wallclock=999999999999999
[WARNING] received newer chunk (slot: 200). overwriting.
[eqvoc] received chunk (slot: 200, from: FakeValidator..., index: 0/3) wallclock=1000000
[WARNING] received older chunk. ignoring.
[eqvoc] received chunk (slot: 200, from: FakeValidator..., index: 1/3) wallclock=1000000
[WARNING] received older chunk. ignoring.
[eqvoc] received chunk (slot: 200, from: FakeValidator..., index: 2/3) wallclock=1000000
[WARNING] received older chunk. ignoring.
# NO "proof complete" message
# NO "verification" attempt
# Proof never assembles!
```

### Slot 300 (Normal - Chunks Assemble, Validation Fails)
```
[eqvoc] received chunk (slot: 300, from: FakeValidator..., index: 0/3)
[eqvoc] received chunk (slot: 300, from: FakeValidator..., index: 1/3)
[eqvoc] received chunk (slot: 300, from: FakeValidator..., index: 2/3)
[eqvoc] proof complete for slot 300, verifying...
[ERROR] proof verification failed: invalid signature
```

## Interpretation

The critical evidence is **what's missing** from slot 200's logs:

1. ✅ Poison chunk accepted (wallclock = 999999999999999)
2. ✅ Legitimate chunks rejected (wallclock < poison value)
3. ❌ **No proof assembly** ("proof complete" never logged)
4. ❌ **No verification attempt** (validation never triggered)

This proves the vulnerability: the wallclock poisoning permanently blocks chunk assembly, preventing equivocation detection.

## Notes

- The PoC uses syntactically valid but semantically invalid proof data (random bytes)
- No actual equivocation occurs - we're testing the chunk assembly mechanism only
- The `from` field uses a fictitious validator identity
- All proofs would fail validation if they reached that stage (by design)
- The vulnerability is demonstrated by the **absence** of validation for slot 200

## Cleanup

The PoC does not modify any persistent state. Simply stop the processes and delete logs if desired:

```bash
# Stop fddev (Ctrl+C in Terminal 1)
# Remove logs
rm -f fddev.log
```
