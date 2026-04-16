# IPC-001: Tango IPC Metadata DoS via Malicious Producer Tile

## Severity
**HIGH**

## Summary
Firedancer's Tango IPC mechanism does not validate producer-controlled metadata fields, allowing a compromised tile to cause denial-of-service in downstream consumer tiles through unbounded loops, out-of-bounds memory access, and sequence number manipulation. This enables lateral movement attacks where compromise of a single upstream tile can cascade to halt the entire validator.

## Affected Components
- `src/tango/fd_tango_base.h:144-166` (fragment metadata structure - no validation)
- `src/tango/fd_tango_base.h:254-256` (chunk pointer conversion - no bounds checking)
- `src/tango/test_frag_rx.c:232-238` (unbounded loop based on sz field)
- `src/tango/mcache/fd_mcache.h:578-605` (sequence number wait loop)
- All tiles consuming Tango IPC messages (QUIC→VERIFY, VERIFY→DEDUP, DEDUP→RESOLV, RESOLV→PACK, PACK→BANK, BANK→POH, POH→SHRED)

## Technical Details

### Background: Tango IPC Architecture

Firedancer implements a lockless IPC mechanism where:
- Each **producer tile** has RW access to its own mcache (metadata) and dcache (data)
- **Consumer tiles** have RO access to producer's mcache/dcache
- Memory isolation is enforced via separate processes with kernel-level page permissions
- Consumers read metadata atomically but **trust all fields without validation**

The mcache contains fragment metadata:
```c
// src/tango/fd_tango_base.h:144-166
union fd_frag_meta {
  struct {
    ulong  seq;     // Sequence number (producer-controlled)
    ulong  sig;     // Signature/pattern (producer-controlled)
    uint   chunk;   // Chunk index in dcache (producer-controlled)
    ushort sz;      // Fragment size in bytes (producer-controlled)
    ushort ctl;     // Control flags (producer-controlled)
    uint   tsorig;  // Origin timestamp (producer-controlled)
    uint   tspub;   // Publish timestamp (producer-controlled)
  };
};
```

**Critical Issue**: All 7 fields are producer-controlled with **ZERO validation**.

### Vulnerability #1: Unbounded Loop via sz Field (CRITICAL)

**Location**: `src/tango/test_frag_rx.c:232-238`

Consumer processing code uses `sz` directly as loop bound:

```c
// Line 200: Extract size from producer-controlled metadata
ulong sz = (ulong)meta->sz;  // NO VALIDATION

// Line 232-238: Loop bound entirely controlled by producer
for( ulong off=0UL; off<sz; off+=128UL ) {
  mask0 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8(
    _mm256_load_si256( (__m256i *) p       ), avx ) );
  mask1 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8(
    _mm256_load_si256( (__m256i *)(p+32UL) ), avx ) );
  mask2 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8(
    _mm256_load_si256( (__m256i *)(p+64UL) ), avx ) );
  mask3 &= _mm256_movemask_epi8( _mm256_cmpeq_epi8(
    _mm256_load_si256( (__m256i *)(p+96UL) ), avx ) );
  p += 128UL;
}
```

**Attack**:
- Producer publishes `sz = 65535` (USHORT_MAX)
- Consumer executes ~512 iterations of expensive AVX operations
- Consumer CPU spins at 100%, misses housekeeping deadlines
- Downstream tiles starve, validator processing halts

**Also vulnerable**: `src/tango/test_frag_tx.c`, `src/tango/bench_frag_tx.c`, `src/disco/dedup/test_dedup.c:225,419`

### Vulnerability #2: Unvalidated Chunk Pointer (CRITICAL)

**Location**: `src/tango/fd_tango_base.h:254-256`

The `chunk` field is used in pointer arithmetic **without bounds checking**:

```c
// Comment says "Assumed in [0,UINT_MAX]" but no runtime validation
FD_FN_CONST static inline void const *
fd_chunk_to_laddr_const( void const * chunk0,
                         ulong        chunk ) {
  return (void const *)(((ulong)chunk0) + (chunk << FD_CHUNK_LG_SZ));
  //                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  //                                       chunk * 64 - UNBOUNDED
}
```

**Used in**: `src/tango/test_frag_rx.c:226`
```c
uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
// p now points to potentially out-of-bounds memory
for( ulong off=0UL; off<sz; off+=128UL ) {
  _mm256_load_si256( (__m256i *) p );  // Arbitrary read!
}
```

**Attack**:
- Producer publishes `chunk = workspace_size/64 + 1000`
- Consumer calculates `p = workspace_base + (chunk * 64)` (out of bounds)
- AVX load instruction reads arbitrary memory
- **Result**: Segmentation fault (consumer crash) OR information disclosure

### Vulnerability #3: Sequence Number Manipulation (HIGH)

**Location**: `src/tango/mcache/fd_mcache.h:578-605`

Consumers wait for sequence numbers in the `FD_MCACHE_WAIT` macro:

```c
for(;;) {  // Unbounded loop
  FD_COMPILER_MFENCE();
  _fd_mcache_wait_seq_found = _fd_mcache_wait_mline->seq;  // Read from shared memory
  FD_COMPILER_MFENCE();
  *_fd_mcache_wait_meta = *_fd_mcache_wait_mline;
  FD_COMPILER_MFENCE();
  ulong _fd_mcache_wait_seq_test = _fd_mcache_wait_mline->seq;  // Re-read
  FD_COMPILER_MFENCE();

  _fd_mcache_wait_seq_diff = fd_seq_diff( _fd_mcache_wait_seq_found,
                                           _fd_mcache_wait_seq_expected );
  int _fd_mcache_wait_done =
    ((_fd_mcache_wait_seq_found==_fd_mcache_wait_seq_test) &
     (_fd_mcache_wait_seq_diff>=0L)) | (!--_fd_mcache_wait_poll_max);

  if( FD_LIKELY( _fd_mcache_wait_done ) ) break;
  FD_SPIN_PAUSE();
}
```

**Attack**: Producer alternates sequence numbers (N, N-1, N, N-1...)
- Consumer detects "overrun" every iteration
- Overrun handling: `seq = seq_found; continue;` (loops back)
- Consumer never advances, stuck in infinite loop

## Attack Scenarios

### Scenario 1: Single Tile Compromise → Validator Halt

**Attack Flow**:
```
1. Attacker compromises NET tile (e.g., packet parser vulnerability)
   ↓
2. NET has WRITE access to its mcache
   ↓
3. Attacker crafts malicious metadata:
      meta->sz = 65535        // Max size
      meta->chunk = 0xFFFFFFFF // Out-of-bounds
      meta->seq = <valid>      // Passes sequence check
   ↓
4. QUIC tiles (consumers) read this metadata
   ↓
5. QUIC tiles enter unbounded loop (512 iterations)
   ↓
6. QUIC tiles CPU at 100%, no output to VERIFY
   ↓
7. VERIFY tiles starve → DEDUP starves → RESOLV starves → PACK starves
   ↓
8. Entire validator stops processing transactions
```

### Scenario 2: Targeted Tile DoS

**Target**: PACK tile (single-instance bottleneck)

```
1. Attacker compromises RESOLV tile
   ↓
2. RESOLV publishes to PACK via resolv_pack link
   ↓
3. Malicious metadata: sz = 65535, chunk = invalid
   ↓
4. PACK tile seizes up on unbounded loop
   ↓
5. No transaction scheduling → validator falls behind
   ↓
6. Validator misses slots, loses rewards
```

### Scenario 3: Cascading Failure via Broadcast Links

**Target**: REPLAY tile (broadcasts to 6+ consumers)

```
1. Attacker compromises SHRED tile
   ↓
2. SHRED publishes to REPLAY via shred_out link
   ↓
3. Malicious metadata causes REPLAY DoS
   ↓
4. REPLAY fails to broadcast replay_out, replay_stake
   ↓
5. Downstream consumers: EXEC, PACK, RESOLV, TOWER, RPC, GOSSIP all starve
   ↓
6. Widespread validator failure
```

## Tile Communication Topology

### Critical Producer→Consumer Links

| Link | Producer | Consumer(s) | Impact if Producer Compromised |
|------|----------|-------------|--------------------------------|
| net_quic | NET | QUIC | DoS all QUIC tiles |
| quic_verify | QUIC | VERIFY | DoS all VERIFY tiles |
| verify_dedup | VERIFY | DEDUP | DoS DEDUP (single bottleneck) |
| dedup_resolv | DEDUP | RESOLV | DoS all RESOLV tiles |
| resolv_pack | RESOLV | PACK | DoS PACK (single bottleneck) |
| pack_bank | PACK | BANK | DoS all BANK tiles |
| bank_poh | BANK | POH | DoS POH (single bottleneck) |
| poh_shred | POH | SHRED | DoS all SHRED tiles |
| gossip_out | GOSSIP | 8+ tiles | DoS VERIFY, SEND, TOWER, RPC, GUI, REPAIR, GOSSVF |
| replay_out | REPLAY | 6+ tiles | DoS EXEC, PACK, RESOLV, TOWER, RPC |

### Single-Instance Bottlenecks (High-Value Targets)

1. **DEDUP** - All VERIFY output funnels here
2. **PACK** - Serializes transaction scheduling
3. **POH** - Serializes proof of history
4. **GOSSIP** - Single gossip protocol instance
5. **REPLAY** - Serializes historical state

Compromising tiles upstream of these bottlenecks has maximum impact.

## Root Cause Analysis

### Design Trade-offs

Tango IPC was designed for:
- ✅ **Zero-copy messaging** - No data copies between tiles
- ✅ **Lock-free synchronization** - No mutex contention
- ✅ **High performance** - Minimal latency overhead
- ✅ **Memory isolation** - Separate processes, kernel-enforced permissions

But sacrificed:
- ❌ **Input validation** - Complete trust in producer metadata
- ❌ **Bounds checking** - No verification of sz, chunk fields
- ❌ **Rate limiting** - No throttling of malicious messages
- ❌ **Authentication** - No cryptographic binding of metadata

### Trust Model

**Assumption**: All tiles are mutually trusted, cooperative components

**Reality**: Process isolation prevents direct memory corruption, BUT:
- Compromised tile can still write to its own mcache
- Downstream consumers must trust this data
- No validation layer between processes

**Gap**: IPC channel becomes lateral movement vector when tile is compromised

### Why Process Isolation Doesn't Prevent This

In production, tiles run as separate processes with:
- ✅ Separate PIDs, separate address spaces
- ✅ Seccomp filters (only 2 syscalls allowed per tile)
- ✅ PID namespaces (tiles cannot signal each other)
- ✅ Capability dropping (CAP_KILL, CAP_SYS_PTRACE removed)

**However**:
- Producer has **WRITE** permission to its mcache (via PROT_READ|PROT_WRITE)
- Consumer has **READ** permission to producer's mcache (via PROT_READ)
- Consumer **cannot write back** (kernel enforces RO protection)
- Consumer **must trust what it reads** (no validation layer)

**Attacker with RCE in producer tile**:
- ❌ Cannot directly corrupt consumer memory (separate address space)
- ❌ Cannot send SIGKILL to consumer (seccomp blocks kill(), PID namespace)
- ❌ Cannot ptrace consumer (seccomp blocks ptrace())
- ✅ **CAN write malicious metadata to mcache** (has PROT_WRITE permission)
- ✅ **CAN cause consumer DoS** (consumer trusts sz, chunk fields)

## Proof of Concept

### Attack Code (Compromised Producer Tile)

```c
// Attacker code running in compromised NET tile with mcache write access
void attack_dos_consumers( fd_frag_meta_t * mcache,
                           ulong depth,
                           ulong seq ) {

  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );

  // Attack vector 1: Unbounded loop
  meta->sz = 65535;  // USHORT_MAX - causes ~512 loop iterations

  // Attack vector 2: Out-of-bounds read
  meta->chunk = 0xFFFFFFFF;  // Far beyond workspace bounds

  // Attack vector 3: Valid sequence to bypass checks
  meta->seq = seq;
  meta->sig = 0xDEADBEEF;
  meta->ctl = 0;

  // Atomically publish
  FD_COMPILER_MFENCE();
  meta->seq = fd_seq_dec( seq, 1UL );  // Mark in-progress
  FD_COMPILER_MFENCE();
  // ... (metadata already written above)
  FD_COMPILER_MFENCE();
  meta->seq = seq;  // Mark published
  FD_COMPILER_MFENCE();

  // Consumer tiles now read this and:
  // - Enter loop for 65535 bytes (512 iterations)
  // - Attempt to read from invalid chunk address
  // - Crash or seize up
}
```

### Victim Behavior (Consumer Tile)

```c
// Consumer tile (e.g., QUIC) reading from compromised NET tile
FD_MCACHE_WAIT( meta, mline, seq_found, seq_diff, poll_max,
                mcache, depth, seq );

// Extract metadata (ALL fields trusted)
ulong chunk = (ulong)meta->chunk;  // 0xFFFFFFFF from attacker
ulong sz    = (ulong)meta->sz;     // 65535 from attacker

// Convert chunk to address (NO BOUNDS CHECK)
uchar const * p = (uchar const *)fd_chunk_to_laddr_const( wksp, chunk );
// p now points to invalid memory

// Enter unbounded loop (NO SIZE VALIDATION)
for( ulong off=0UL; off<sz; off+=128UL ) {  // 512 iterations!
  // Each iteration: 4 AVX loads + fence operations
  _mm256_load_si256( (__m256i *) p );  // May crash on invalid address
  p += 128UL;
}

// Consumer CPU at 100%, no forward progress
// Downstream tiles starve
```

## Recommended Mitigations

### Priority 1: Input Validation (Required)

**Add bounds checking on all metadata fields:**

```c
// src/tango/fd_tango_base.h - Add validation function
static inline int
fd_frag_meta_validate( fd_frag_meta_t const * meta,
                       ulong workspace_chunks,
                       ushort max_frag_sz ) {

  // Validate chunk is within workspace bounds
  if( FD_UNLIKELY( meta->chunk >= workspace_chunks ) ) {
    FD_LOG_WARNING(( "invalid chunk %u >= %lu", meta->chunk, workspace_chunks ));
    return 0;
  }

  // Validate size is within limits
  if( FD_UNLIKELY( meta->sz > max_frag_sz ) ) {
    FD_LOG_WARNING(( "invalid sz %u > %u", meta->sz, max_frag_sz ));
    return 0;
  }

  // Validate control bits are sane
  if( FD_UNLIKELY( (meta->ctl & ~FD_FRAG_META_CTL_ALL_VALID_BITS) ) ) {
    FD_LOG_WARNING(( "invalid ctl bits 0x%x", meta->ctl ));
    return 0;
  }

  return 1;  // Valid
}
```

**Use in consumer code:**

```c
// src/tango/test_frag_rx.c - Validate before processing
FD_MCACHE_WAIT( meta, mline, seq_found, seq_diff, poll_max,
                mcache, depth, seq );

// VALIDATE METADATA BEFORE USE
if( FD_UNLIKELY( !fd_frag_meta_validate( meta, workspace_chunks, FD_TPU_MTU ) ) ) {
  // Invalid metadata - log and skip
  FD_LOG_WARNING(( "received invalid metadata at seq %lu. skipping.", seq ));
  seq = fd_seq_inc( seq, 1UL );
  continue;
}

// Now safe to use metadata
ulong chunk = (ulong)meta->chunk;  // Known to be < workspace_chunks
ulong sz    = (ulong)meta->sz;     // Known to be <= FD_TPU_MTU
```

### Priority 2: Bounds Checking in Pointer Conversion

```c
// src/tango/fd_tango_base.h - Add checked version
static inline void const *
fd_chunk_to_laddr_const_checked( void const * chunk0,
                                 ulong        chunk,
                                 ulong        chunk_max ) {
  if( FD_UNLIKELY( chunk >= chunk_max ) ) {
    FD_LOG_ERR(( "chunk %lu >= chunk_max %lu", chunk, chunk_max ));
    return NULL;  // Or handle error appropriately
  }
  return (void const *)(((ulong)chunk0) + (chunk << FD_CHUNK_LG_SZ));
}
```

### Priority 3: Loop Iteration Limits

```c
// src/tango/test_frag_rx.c - Add iteration limit
#define MAX_SAFE_ITERATIONS 512  // ~65536 bytes / 128 bytes per iteration

ulong iterations = 0;
for( ulong off=0UL; off<sz; off+=128UL ) {
  if( FD_UNLIKELY( ++iterations > MAX_SAFE_ITERATIONS ) ) {
    FD_LOG_WARNING(( "excessive iterations %lu. potential attack.", iterations ));
    break;
  }
  // ... AVX operations
}
```

### Priority 4: Sequence Number Rate Limiting

```c
// Detect rapid sequence number changes (potential manipulation)
ulong seq_change_count = 0;
long last_seq_change_ts = 0;

if( fd_seq_ne( seq_found, seq ) ) {
  long now = fd_log_wallclock();
  if( now - last_seq_change_ts < 1000000000L ) {  // < 1 second
    seq_change_count++;
    if( seq_change_count > 10 ) {
      FD_LOG_WARNING(( "excessive sequence changes. potential attack." ));
      // Consider halting or rate-limiting
    }
  } else {
    seq_change_count = 1;
  }
  last_seq_change_ts = now;
}
```

### Defense in Depth: Cryptographic Authentication (Optional)

**Extend metadata with HMAC:**

```c
union fd_frag_meta {
  struct {
    ulong  seq;
    ulong  sig;
    uint   chunk;
    ushort sz;
    ushort ctl;
    uint   tsorig;
    uint   tspub;
    uchar  hmac[32];  // HMAC-SHA256 over (seq, sig, chunk, sz, ctl)
  };
};

// Producer signs metadata
void fd_mcache_publish_signed( fd_frag_meta_t * mcache,
                               ulong depth, ulong seq, /* ... */,
                               uchar const * shared_key ) {
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );

  // Write fields
  meta->seq = seq;
  meta->sig = sig;
  meta->chunk = chunk;
  meta->sz = sz;
  meta->ctl = ctl;

  // Compute HMAC
  uchar hash[32];
  fd_hmac_sha256( meta, offsetof(fd_frag_meta_t, hmac), shared_key, 32, hash );
  memcpy( meta->hmac, hash, 32 );

  // Publish atomically
  FD_COMPILER_MFENCE();
  meta->seq = fd_seq_dec( seq, 1UL );
  FD_COMPILER_MFENCE();
  // ...
}

// Consumer verifies HMAC
int fd_frag_meta_verify_hmac( fd_frag_meta_t const * meta,
                              uchar const * shared_key ) {
  uchar expected_hmac[32];
  fd_hmac_sha256( meta, offsetof(fd_frag_meta_t, hmac), shared_key, 32, expected_hmac );
  return fd_memeq( meta->hmac, expected_hmac, 32 );
}
```

**Note**: This adds overhead but provides cryptographic guarantee against tampering.

## Verification

### Test Cases

```c
// Test unbounded size validation
void test_frag_meta_validate_sz() {
  fd_frag_meta_t meta = {0};

  meta.sz = 1024;
  assert( fd_frag_meta_validate( &meta, 1000, 2048 ) == 1 );  // Valid

  meta.sz = 65535;
  assert( fd_frag_meta_validate( &meta, 1000, 2048 ) == 0 );  // Invalid
}

// Test chunk bounds validation
void test_frag_meta_validate_chunk() {
  fd_frag_meta_t meta = {0};

  meta.chunk = 999;
  assert( fd_frag_meta_validate( &meta, 1000, 2048 ) == 1 );  // Valid

  meta.chunk = 1000;
  assert( fd_frag_meta_validate( &meta, 1000, 2048 ) == 0 );  // Invalid

  meta.chunk = 0xFFFFFFFF;
  assert( fd_frag_meta_validate( &meta, 1000, 2048 ) == 0 );  // Invalid
}

// Test consumer behavior with malicious metadata
void test_consumer_malicious_metadata() {
  // Setup: Create mcache with malicious metadata
  fd_frag_meta_t * mcache = /* ... */;
  fd_frag_meta_t * meta = mcache + fd_mcache_line_idx( seq, depth );

  meta->sz = 65535;  // Malicious
  meta->chunk = 0xFFFFFFFF;  // Malicious
  meta->seq = seq;

  // Consumer should detect and reject
  int valid = fd_frag_meta_validate( meta, workspace_chunks, FD_TPU_MTU );
  assert( valid == 0 );

  // Consumer should NOT process this metadata
  // Should skip to next sequence number
}
```

### Fuzzing Targets

```bash
# Fuzz metadata fields
AFL_INPUT=malicious_metadata.bin \
AFL_OUTPUT=./fuzz_output \
afl-fuzz -i input_corpus -o fuzz_output -- \
  ./test_frag_rx @@

# Focus on sz and chunk fields
# Monitor for hangs (unbounded loops) and crashes (invalid pointers)
```

## Status
- **Discovered**: 2025-11-10
- **Severity**: HIGH
- **Exploitability**: HIGH (requires RCE in one tile, but enables lateral movement)
- **Impact**: HIGH (validator DoS, cascading failure)
- **Priority**: HIGH (add validation layer)

## References

1. **Firedancer Tango IPC Documentation**:
   - `SR/IPC_Messaging.md` - Tango IPC design
   - `SR/Architecture.md` - Tile architecture and trust boundaries

2. **Code Locations**:
   - `src/disco/topo/fd_topob.c:198-225` - Memory permission configuration
   - `src/util/shmem/fd_shmem_user.c:204` - Kernel-enforced PROT_READ/PROT_WRITE
   - `src/util/sandbox/fd_sandbox.c` - Seccomp filters and capability dropping

3. **Tile Topology**:
   - `src/app/firedancer/topology.c` - Production tile communication graph
   - Main pipeline: NET → QUIC → VERIFY → DEDUP → RESOLV → PACK → BANK → POH → SHRED

4. **Related Vulnerabilities**:
   - Lack of input validation in IPC mechanisms
   - Trust boundaries in multi-process architectures
   - Lateral movement via shared memory channels

## Conclusion

Firedancer's Tango IPC provides excellent performance and memory isolation, but lacks input validation on producer-controlled metadata. A compromised tile can leverage its write access to mcache to cause denial-of-service in downstream consumers through unbounded loops, invalid memory access, or sequence manipulation.

**Key Insights**:
1. Process isolation prevents direct memory corruption but NOT IPC-based DoS
2. Seccomp and capability restrictions prevent traditional process attacks
3. IPC metadata channel becomes primary lateral movement vector
4. Single-instance bottlenecks (DEDUP, PACK, POH) amplify impact
5. Compromising early pipeline tiles (QUIC, VERIFY) has cascading effect

**Immediate mitigation**: Add validation layer for sz, chunk, and control fields before consumer processing. This provides defense-in-depth against compromised tiles while maintaining Tango's performance characteristics.
