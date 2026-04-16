# IPC Messaging (Tango) - Security Analysis

**Components:** Mcache, Dcache, Tcache, Flow Control, CNC
**Source:** `/home/user/firedancer/src/tango/`
**Analysis Date:** November 6, 2025

---

## Executive Summary

Tango implements lock-free inter-process communication for Firedancer tiles. Analysis identified **2 medium-severity** race conditions and **1 medium** PID reuse vulnerability alongside strong defensive mechanisms.

### Key Findings

| ID | Severity | Component | Issue | Location |
|----|----------|-----------|-------|----------|
| 1 | **MEDIUM** | Mcache | Message reordering (TOCTOU) | `tango/mcache/fd_mcache.h:578` |
| 2 | **MEDIUM** | CNC | PID reuse vulnerability | `tango/cnc/fd_cnc.c:176` |
| 3 | **MEDIUM** | Tcache | Infinite loop risk | `tango/tcache/fd_tcache.h:287` |

### Security Strengths

- ✅ Lock-free communication (no deadlocks)
- ✅ Sequence number ordering (detects loss)
- ✅ Overrun detection (consumer awareness)
- ✅ Flow control prevents buffer exhaustion
- ✅ Explicit memory ownership (RO/RW mappings)

---

## Tango Architecture

### Design Philosophy

```
Producer Tile                    Consumer Tile
    │                                 │
    ├─ Write data to DCACHE          │
    │  (64-byte aligned chunks)       │
    │                                 │
    ├─ Write metadata to MCACHE      │
    │  (header: seq, sig, chunk, sz)  │
    │                                 │
    ├─ Atomic seq number update ─────┼─▶ Poll MCACHE
    │                                 │   (spin on seq)
    │                                 │
    │                                 ├─ Read metadata
    │                                 │   (validates seq)
    │                                 │
    │                                 └─ Read from DCACHE
```

### Key Components

1. **Mcache** - Metadata cache (packet headers, transaction info)
2. **Dcache** - Data cache (payloads, large data)
3. **Tcache** - Tag cache (deduplication keys)
4. **Fseq** - Flow sequence tracking
5. **Fctl** - Flow control (backpressure)
6. **CNC** - Command and control channel

---

## Mcache (Metadata Cache)

### Location

**Source:** `/home/user/firedancer/src/tango/mcache/`

### Architecture

**Purpose:** Share transaction metadata between tiles

**Structure:**
```c
struct fd_mcache_line {
  ulong seq;      /* Sequence number (atomic) */
  ulong sig;      /* Signature/tag (64-bit) */
  uint  chunk;    /* Chunk index (>>6) */
  ushort sz;      /* Size in bytes */
  ushort ctl;     /* Control bits */
  uint  tsorig;   /* Origin timestamp */
  uint  tspub;    /* Publish timestamp */
};
```

**Ring Buffer:**
- Power-of-2 depth (default: 16384 lines)
- Lock-free single producer, multiple consumer
- Wraparound via modulo arithmetic

---

### MEDIUM: Message Reordering (TOCTOU)

**File:** `fd_mcache.h`, Lines 578-605

**Macro:** `FD_MCACHE_WAIT`

```c
/* Read sequence atomically */
_seq_found = _mline->seq;  /* atomic read */
FD_COMPILER_MFENCE();

/* Copy metadata (NOT atomic) */
*_meta = *_mline;  /* Multi-word copy */
FD_COMPILER_MFENCE();

/* Re-read sequence */
_seq_test = _mline->seq;  /* atomic read */

/* Check if overwritten */
if( FD_UNLIKELY( fd_seq_ne(_seq_test, _seq_found) ) ) {
  /* Overrun detected, retry */
}
```

**Race Condition:**
1. Consumer reads `seq` (atomic)
2. **Gap:** Producer updates metadata
3. Consumer copies metadata (non-atomic, possibly partial)
4. Producer updates `seq` again
5. Consumer re-reads `seq` (detects mismatch)

**Attack Scenario:**
```
Producer writes at line rate:
- seq=1000, metadata_A
- seq=1001, metadata_B (overwrites during consumer copy)

Consumer:
1. Reads seq=1000
2. Starts copying metadata
3. Producer writes seq=1001, metadata_B (mid-copy)
4. Consumer finishes copying (gets mixed data)
5. Re-reads seq=1001 (detects overrun)
6. Retries, but saw partial state
```

**Impact:** MEDIUM
- Consumer sees inconsistent metadata briefly
- Detected via sequence number check
- Consumer retries on detection
- Documented behavior

**Mitigation Status:** DOCUMENTED
- Overrun detection via `seq_diff` check
- Consumer must handle retries
- Comment: "might observe torn read" (line 436-443)

**Recommendation:**
- Already mitigated by design
- Document consumer retry requirements
- Consider atomic metadata copy (may impact performance)

---

### Initialization Security

**File:** `fd_mcache.c`, Lines 32-78

**Function:** `fd_mcache_new()`

```c
/* Validate parameters */
if( FD_UNLIKELY( !depth || (depth & (depth-1UL)) ) ) {
  FD_LOG_WARNING(( "bad depth" ));
  return NULL;
}

/* Initialize header */
hdr->magic = FD_MCACHE_MAGIC;
hdr->depth = depth;

/* Set all lines to invalid state */
for( ulong i=0; i<depth; i++ ) {
  line[i].seq = i - 1UL;  /* seq-1 */
  line[i].sig = 0UL | FD_MCACHE_SIG_ERR;  /* Error bit set */
}
```

**Security:**
- ✅ Power-of-2 depth validation
- ✅ Magic number protection
- ✅ All lines initialized to invalid
- ✅ Prevents uninitialized reads

---

## Dcache (Data Cache)

### Location

**Source:** `/home/user/firedancer/src/tango/dcache/`

### Architecture

**Purpose:** Store large data payloads (packet contents, transaction data)

**Layout:**
```
┌─────────────────────────────────────┐
│  Header (metadata)                  │
├─────────────────────────────────────┤
│  Guard Region (3968 bytes)          │  ← Prevents accidental writes
├─────────────────────────────────────┤
│  Data Region                        │
│  (64-byte aligned chunks)           │
│  chunk0: [data0]                    │
│  chunk1: [data1]                    │
│  ...                                │
└─────────────────────────────────────┘
```

**Chunk Addressing:**
- 64-byte alignment (performance)
- Chunk index fits in 32-bit
- Supports wraparound

---

### Guard Region Protection

**File:** `fd_dcache.h`, Lines 219-270

**Constant:** `FD_DCACHE_GUARD_FOOTPRINT = 3968`

**Purpose:** Prevent buffer overrun from header into data

**Security:**
- ✅ 3968-byte gap between header and data
- ✅ Catches accidental writes
- ⚠️ Not cryptographic protection
- Assumes well-behaved producers

---

### Integer Overflow Risk

**File:** `fd_dcache.h`, Line 268

**Function:** `fd_dcache_compact_next()`

```c
/* Calculate next chunk position */
chunk += ((sz + (2UL*FD_CHUNK_SZ-1UL)) >> (1+FD_CHUNK_LG_SZ)) << 1;

return fd_ulong_if( chunk > wmark, chunk0, chunk );
```

**Issue:**
- Addition `sz + (2UL*FD_CHUNK_SZ-1UL)` can overflow
- If `sz` is near `ULONG_MAX`, wraps around

**Mitigation:**
- Documentation states `sz` assumed in `[0, mtu]`
- MTU typically 1232-1500 bytes
- Overflow impossible with valid inputs

**Impact:** LOW
- Requires malformed `sz` parameter
- Validated at call sites
- Not exploitable in practice

---

### Memory Initialization

**File:** `fd_dcache.c`, Lines 70-78

```c
/* Zero header */
fd_memset( shmem, 0, sizeof(fd_dcache_private_hdr_t) );

/* Zero app region */
fd_memset( (uchar*)shmem + hdr->app_off, 0, app_sz );
```

**Issue:** Data region NOT zeroed

**Impact:** MEDIUM
- Uninitialized data in dcache
- Information leakage if dcache reused
- Sensitive data from previous allocations

**Recommendation:**
```c
/* Zero entire data region */
fd_memset( (uchar*)shmem + data_off, 0, data_sz );
```

---

## Tcache (Tag Cache)

### Location

**Source:** `/home/user/firedancer/src/tango/tcache/`

### Architecture

**Purpose:** Deduplication cache (transaction signature tags)

**Hash Table:**
- Linear probing on collision
- 64-bit tags
- Sparse map (low occupancy)

---

### MEDIUM: Infinite Loop Risk

**File:** `fd_tcache.h`, Lines 281-295

**Macro:** `FD_TCACHE_QUERY`

```c
/* Linear probe */
for(;;) {
  ulong _tag = _map[ _idx ];
  _found = (_tag == _target);
  
  if( FD_LIKELY( _found | fd_tcache_tag_is_null(_tag) ) ) 
    break;  /* Found or empty slot */
  
  _idx = fd_tcache_map_next( _idx, _cnt );  /* Next probe */
}
```

**Issue:**
- No iteration limit
- If map is full and tag not present, infinite loop
- Only breaks on found or NULL

**Attack Scenario:**
```
1. Fill tcache with non-null tags
2. Query for non-existent tag
3. Linear probe never finds NULL
4. Infinite loop → DoS
```

**Mitigation:**
- Design assumes sparse map (lines 44-57)
- Occupancy kept low (< 50%)
- NULL slots always present

**Impact:** MEDIUM
- Requires corrupted tcache state
- Unlikely in normal operation
- Could occur under memory corruption

**Recommendation:**
```c
/* Add iteration limit */
ulong iterations = 0;
for(;;) {
  if( FD_UNLIKELY( ++iterations > _cnt ) ) {
    /* Table full, abort */
    _found = 0;
    break;
  }
  /* ... existing probe logic ... */
}
```

---

## Command and Control (CNC)

### Location

**Source:** `/home/user/firedancer/src/tango/cnc/`

### Architecture

**Purpose:** Tile lifecycle management (start, stop, heartbeat)

**State Machine:**
```
BOOT → RUN → USER → HALT → FAIL
             ↓
           (custom states)
```

---

### MEDIUM: PID Reuse Vulnerability

**File:** `fd_cnc.c`, Lines 176-200

```c
/* Check if process is dead */
if( cnc_pid != my_pid && kill( (pid_t)cnc_pid, 0 ) ) {
  int err = errno;
  if( FD_LIKELY( err == ESRCH ) ) {  /* Process doesn't exist */
    
    /* Race window here! */
    
    /* Try to acquire lock */
    if( FD_LIKELY( FD_ATOMIC_CAS(&cnc->lock, cnc_pid, my_pid) == cnc_pid ) ) {
      /* Got lock, recover state */
      ulong signal = fd_cnc_signal_query( cnc );
      /* ... */
    }
  }
}
```

**Race Condition:**
1. Process A dies, releases lock with PID=1234
2. Thread 1 calls `kill(1234, 0)` → ESRCH (process dead)
3. **Gap:** OS reuses PID 1234 for new process B
4. Thread 1 tries CAS with old PID 1234
5. New process B now has inherited lock with stale signal

**Impact:** MEDIUM
- New process inherits stale state
- Signal from dead process seen by new process
- Causes unexpected behavior

**Mitigation:** Documented assumption
- Comment line 189: "assumes no pid reuse between kill and cas"
- Rare on modern Linux (PID space exhaustion)

**Recommendation:**
```c
/* Use pidfd or eventfd for robust death detection */
int pidfd = syscall(SYS_pidfd_open, cnc_pid, 0);
if( pidfd < 0 ) {
  /* Process dead or invalid */
  /* Safely acquire lock */
}
close(pidfd);
```

---

### Heartbeat Race

**File:** `fd_cnc.h`, Lines 264-270

```c
static inline void 
fd_cnc_heartbeat( fd_cnc_t * cnc, long now ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( cnc->heartbeat ) = now;  /* Only compiler fence */
  FD_COMPILER_MFENCE();
}
```

**Issue:**
- Only compiler fences, not memory barriers
- Heartbeat write not atomic
- Signal field can race with heartbeat

**Impact:** LOW
- Eventual consistency model
- Acceptable for heartbeat monitoring
- Not safety-critical

---

## Flow Control

### Location

**Source:** `/home/user/firedancer/src/tango/fctl/` and `fseq/`

### Architecture

**Purpose:** Backpressure to prevent buffer overflow

**Mechanism:**
```
Producer                    Consumer
  │                            │
  ├─ Check consumer seq ───────┤
  │  (via fseq)                │
  │                            │
  ├─ Calculate credits         │
  │  (available buffer space)  │
  │                            │
  └─ Block if credits == 0     │
     (backpressure)            │
```

---

### Overflow Handling

**File:** `fd_fctl.h`, Lines 318-365

```c
/* Robust against sequence number overflow */
ulong rx_cr_query = (ulong)fd_long_max(
  rx[ rx_idx ].cr_max - fd_long_max( fd_seq_diff( tx_seq, rx_seq ), 0L ),
  0L
);
```

**Security:**
- ✅ Uses `fd_seq_diff()` for wraparound-safe comparison
- ✅ `fd_long_max()` prevents negative credits
- ✅ Explicit overflow handling (lines 318-355 document)

**Assessment:** STRONG

---

## Security Recommendations

### Immediate Actions

1. **Zero Dcache Data Region** (`fd_dcache.c:70`)
   ```c
   fd_memset( data_region, 0, data_sz );
   ```

2. **Add Tcache Iteration Limit** (`fd_tcache.h:287`)
   ```c
   if( ++iterations > map_cnt ) break;
   ```

### High Priority

3. **Fix CNC PID Reuse** (`fd_cnc.c:176`)
   - Use `pidfd_open()` for process tracking
   - Add generation counter with PID

4. **Document TOCTOU Behavior** (`fd_mcache.h:578`)
   - Explicit consumer retry requirements
   - Example retry loop

### Medium Priority

5. **Add Heartbeat Atomics**
   - Use `atomic_store()` for heartbeat writes
   - Memory barriers for cross-core visibility

6. **Validate Dcache Size Parameters**
   - Explicit bounds checking
   - Reject sizes near ULONG_MAX

---

## Testing Recommendations

### Stress Testing

1. **Mcache Overrun Detection**
   - Producer at max rate
   - Slow consumer
   - Verify retry behavior

2. **Tcache Capacity**
   - Fill to 90% capacity
   - Query non-existent tags
   - Measure probe lengths

3. **CNC PID Reuse**
   - Rapid process creation/destruction
   - PID space exhaustion
   - State inheritance

### Race Condition Testing

1. **Concurrent Mcache Access**
   - Multiple producers (if supported)
   - Verify sequence ordering

2. **CNC Lock Acquisition**
   - Simultaneous lock attempts
   - Process death during acquisition

---

## Positive Security Features

### Lock-Free Design

**Benefits:**
- No deadlocks possible
- No priority inversion
- Predictable latency

**Trade-offs:**
- TOCTOU races (mitigated)
- Requires careful ordering

---

### Explicit Memory Ownership

**Pattern:**
```
Producer: RW access to dcache
Consumer: RO access to dcache

Prevents:
- Consumer corruption of data
- Accidental writes
```

**Enforcement:**
- Memory mapped with appropriate permissions
- Tile sandbox prevents escalation

---

### Sequence Number Ordering

**Benefits:**
- Detects message loss
- Detects reordering
- Enables overrun detection

**Properties:**
- 64-bit wraparound safe
- Atomic updates
- Monotonic increasing

---

## References

- Source: `/home/user/firedancer/src/tango/`
- Related: `SR/Architecture.md`, `SR/Memory_Safety.md`

**END OF IPC MESSAGING ANALYSIS**
