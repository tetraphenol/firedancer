# State Management (Funk/Groove/Vinyl) - Security Analysis

**Components:** Funk (Transactional KV), Groove (Volume Storage), Vinyl (Index Abstraction)
**Source:** `/home/user/firedancer/src/funk/`, `/src/groove/`, `/src/vinyl/`
**Analysis Date:** November 6, 2025

---

## Executive Summary

Firedancer's state management layer implements a three-tier architecture with transactional semantics, persistent storage, and lock-free indexing. Analysis identified **1 medium-severity** HashDoS vulnerability and **strong defensive mechanisms** throughout.

### Key Findings

| ID | Severity | Component | Issue | Location |
|----|----------|-----------|-------|----------|
| 1 | **MEDIUM** | Funk | HashDoS on 32-bit architectures | `funk/fd_funk_base.h:203` |
| 2 | **LOW** | Funk | Crash-state inheritance | `funk/fd_funk.c:158` |
| 3 | **INFO** | Vinyl | Probe sequence traversal | `vinyl/meta/fd_vinyl_meta.c:31` |

### Security Strengths

- ✅ Transaction isolation with cycle detection
- ✅ Use-after-free detection via volatile reads
- ✅ Comprehensive bounds checking (28-bit size limits)
- ✅ Corruption detection with FD_CRIT assertions
- ✅ Atomic CAS operations prevent race conditions
- ✅ Memory fences ensure proper ordering
- ✅ Finite termination guarantees prevent infinite loops

---

## Architecture Overview

### Three-Tier Design

```
┌─────────────────────────────────────────┐
│  FUNK - Transactional Key-Value Store   │
│  - ACID transaction semantics           │
│  - Transaction tree (parent/child)      │
│  - Copy-on-write isolation              │
│  - Cycle detection                      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  GROOVE - Volume Storage Layer          │
│  - 1GB fixed-size volumes               │
│  - Magic number validation              │
│  - Bitfield metadata (24-bit sizes)     │
│  - Corruption detection                 │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  VINYL - Index/Map Abstraction          │
│  - Linear probing hash table            │
│  - Lock-free concurrent reads           │
│  - Probe sequence repair                │
│  - Finite termination guarantees        │
└─────────────────────────────────────────┘
```

### Data Flow

```
Transaction Begin
     │
     ├─ Create child transaction (funk_txn_new)
     │  - Validates parent is ACTIVE
     │  - Adds to transaction tree
     │  - Cycle detection
     │
     ├─ Modify records (funk_rec_modify)
     │  - Copy-on-write semantics
     │  - Bounds checking (28-bit val_sz)
     │  - Pool allocation from funk
     │
     ├─ Vinyl indexing (vinyl_meta_query)
     │  - Linear probe with termination
     │  - Memo-based initial hash
     │  - Corruption detection
     │
     └─ Commit/Cancel
        - Atomic state transition (CAS)
        - Memory fence before publish
        - Groove persistence
```

---

## Funk (Transactional Key-Value Store)

### Location

**Source:** `/home/user/firedancer/src/funk/`

### Purpose

ACID-compliant transactional key-value store with:
- Transaction tree hierarchy (parent/child transactions)
- Copy-on-write record isolation
- Atomic publish/cancel operations
- Cycle detection in transaction trees

---

### MEDIUM: HashDoS on 32-bit Architectures

**File:** `fd_funk_base.h`, Lines 198-223

**Conditional Compilation:**

```c
#if FD_HAS_INT128

/* xxHash3 with 128-bit multiplication (lines 158-190) */
static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       rec_type,
                       ulong       seed ) {
  seed ^= rec_type;
  /* ... xxHash3 implementation ... */
  return acc;
}

#else

/* Fallback hash function */

/* FIXME This version is vulnerable to HashDoS */

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       rec_type,
                       ulong       seed ) {
  seed ^= rec_type;
  return (fd_ulong_hash( seed ^ (1UL<<0) ^ FD_LOAD( ulong, key+ 0 ) )   ^
          fd_ulong_hash( seed ^ (1UL<<1) ^ FD_LOAD( ulong, key+ 8 ) ) ) ^
         (fd_ulong_hash( seed ^ (1UL<<2) ^ FD_LOAD( ulong, key+16 ) ) ^
          fd_ulong_hash( seed ^ (1UL<<3) ^ FD_LOAD( ulong, key+24 ) ) );
}

#endif /* FD_HAS_INT128 */
```

**Issue:**

On architectures without 128-bit integer support (32-bit ARM, older x86):
1. Falls back to `fd_ulong_hash()` - non-cryptographic hash
2. Predictable hash collisions possible
3. Attacker can craft keys that all hash to same bucket

**Attack Scenario:**

```
Attacker crafts transaction keys K1, K2, ..., Kn such that:
  fd_ulong_hash(K1) == fd_ulong_hash(K2) == ... == fd_ulong_hash(Kn)

Linear probing degrades to O(n):
1. Insert K1 at index H
2. Insert K2 at index H+1 (collision)
3. Insert K3 at index H+2 (collision)
...
n. Insert Kn at index H+n-1 (collision)

Lookup/Insert time: O(n) instead of O(1)
```

**Impact:** MEDIUM

- Only affects 32-bit platforms (rare for validators)
- Modern x86_64 has `uint128` support
- Requires crafted transaction keys (not arbitrary data)
- Linear probing still terminates (no infinite loop)

**Mitigation Status:** DOCUMENTED

- Comment line 203: "This version is vulnerable to HashDoS"
- Fixme marker present
- xxHash3 used on all modern platforms

**Recommendation:**

```c
#if !FD_HAS_INT128
/* Use BLAKE3 or SipHash for DoS resistance */
#include "../ballet/blake3/fd_blake3.h"

FD_FN_PURE static inline ulong
fd_funk_rec_key_hash1( uchar const key[ 32 ],
                       ulong       rec_type,
                       ulong       seed ) {
  fd_blake3_t blake;
  fd_blake3_init( &blake );
  fd_blake3_append( &blake, &seed, sizeof(seed) );
  fd_blake3_append( &blake, &rec_type, sizeof(rec_type) );
  fd_blake3_append( &blake, key, 32 );
  uchar digest[32];
  fd_blake3_fini( &blake, digest );
  return FD_LOAD( ulong, digest );
}
#endif
```

---

### Use-After-Free Detection

**File:** `fd_funk_txn.h`, Lines 254-281

**Mechanism:**

```c
static inline void
fd_funk_txn_state_assert( fd_funk_txn_t const * txn,
                          uint                  want ) {

  /* Volatile read forces actual memory load */
  uint have = FD_VOLATILE_CONST( txn->state );

  if( FD_UNLIKELY( want!=have ) ) {
    FD_LOG_CRIT(( "Invariant violation detected on funk txn: expected state %u-%s, found state %u-%s",
                  want, fd_funk_txn_state_str( want ),
                  have, fd_funk_txn_state_str( have ) ));
  }
}

static void
fd_funk_txn_xid_assert( fd_funk_txn_t const *     txn,
                        fd_funk_txn_xid_t const * xid ) {

  /* Volatile reads ensure fresh values */
  uint              found_state = FD_VOLATILE_CONST( txn->state );
  fd_funk_txn_xid_t found_xid   = FD_VOLATILE_CONST( txn->xid   );

  int xid_ok    = fd_funk_txn_xid_eq( &found_xid, xid );
  int state_ok  = found_state==FD_FUNK_TXN_STATE_ACTIVE;

  if( FD_UNLIKELY( !xid_ok || !state_ok ) ) {
    if( !xid_ok ) {
      /* Transaction XID changed → use-after-free */
      FD_LOG_CRIT(( "Data race detected: funk txn %p %lu:%lu use-after-free",
                    (void *)txn,
                    xid->ul[0], xid->ul[1] ));
    } else {
      /* Transaction in wrong state → race condition */
      FD_LOG_CRIT(( "Data race detected: funk txn %p %lu:%lu in invalid state %u-%s",
                    (void *)txn,
                    xid->ul[0], xid->ul[1],
                    found_state, fd_funk_txn_state_str( found_state ) ));
    }
  }
}
```

**Security Properties:**

1. **FD_VOLATILE_CONST** prevents compiler optimization
   - Forces actual memory read
   - Detects concurrent modifications

2. **XID comparison** detects transaction reuse
   - If XID changed, pointer was freed and reallocated
   - Catches use-after-free immediately

3. **State validation** detects race conditions
   - ACTIVE → CANCEL/PUBLISH transitions
   - Crashes on unexpected state

**Assessment:** STRONG

---

### Transaction Cycle Detection

**File:** `fd_funk_txn.c`, Lines 146-196

**Algorithm:**

```c
/* Traverse transaction tree from child to root */
fd_funk_txn_t * parent = txn;
for(;;) {
  if( FD_UNLIKELY( !parent ) ) break;  /* Reached root */

  /* Mark visited with generation tag */
  ulong parent_idx = fd_funk_txn_idx( txn_pool, parent );

  /* Check if already visited (cycle detected) */
  if( FD_UNLIKELY( txn_pool->ele[parent_idx].tag ) ) {
    FD_LOG_ERR(( "Cycle detected in transaction tree" ));
    return -1;
  }

  txn_pool->ele[parent_idx].tag = tag;
  parent = fd_funk_txn_parent( parent );
}
```

**Security:**

- ✅ Prevents infinite loops in transaction traversal
- ✅ Tag-based visited tracking (generation counter)
- ✅ O(depth) cycle detection
- ✅ Prevents DoS via circular transaction chains

---

### Integer Overflow Protection

**File:** `fd_funk_rec.h`, Lines 39-48

**Structure:**

```c
struct fd_funk_rec_private {
  fd_funk_rec_key_t key;     /* 32-byte key */

  ulong prev;                /* Previous record in list */
  ulong next;                /* Next record in list */
  ulong map_next;            /* Next in hash chain */

  /* Bitfield size limits */
  uint val_sz  : 28;         /* Value size (max 268MB) */
  uint val_max : 28;         /* Allocated size (max 268MB) */
  uint flags   : 8;          /* Flags */

  uint txn_cidx;             /* Transaction index */
  ulong tag;                 /* Tag for cycle detection */
  ulong val_gaddr;           /* Value global address */
};
```

**Protection:**

```c
/* From fd_funk_val.c:57 */
rec->val_sz  = (uint)(sz & FD_FUNK_REC_VAL_MAX);
rec->val_max = (uint)(fd_ulong_min(new_val_max, FD_FUNK_REC_VAL_MAX) & FD_FUNK_REC_VAL_MAX);

/* FD_FUNK_REC_VAL_MAX = (1UL<<28)-1 = 268435455 bytes */
```

**Security:**

- ✅ 28-bit size limit prevents overflow in bitfield
- ✅ Explicit masking with `FD_FUNK_REC_VAL_MAX`
- ✅ Double bounds checking (min + mask)
- ✅ Compile-time assertion if limit exceeded

---

### LOW: Crash-State Inheritance

**File:** `fd_funk.c`, Lines 157-164

**Function:** `fd_funk_join()`

```c
if( FD_UNLIKELY( magic != FD_FUNK_MAGIC ) ) {

  /* Detect crash during critical section */
  if( FD_UNLIKELY( magic == FD_FUNK_MAGIC+1 ) ) {
    FD_LOG_WARNING(( "funk appears to have crashed mid-critical-section, attempting to continue" ));

    /* Restore magic and continue */
    shmem->magic = FD_FUNK_MAGIC;
  } else {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
}
```

**Issue:**

1. Funk uses `magic+1` during critical section to detect crashes
2. If process crashes with `magic+1`, state may be inconsistent
3. `fd_funk_join()` attempts recovery by restoring magic
4. No verification that data structures are actually consistent

**Attack Scenario:**

```
Thread 1:
1. Sets magic = FD_FUNK_MAGIC+1 (enter critical section)
2. Modifies transaction tree
3. [Process crashes before restoring magic]

Later restart:
1. fd_funk_join() sees magic+1
2. Restores magic to FD_FUNK_MAGIC
3. Continues with potentially inconsistent state
4. Corrupted transaction tree may cause crashes/exploits
```

**Impact:** LOW

- Requires process crash at exact moment
- Crash likely causes validator restart anyway
- Transaction tree has cycle detection
- Most operations have corruption checks

**Recommendation:**

```c
if( magic == FD_FUNK_MAGIC+1 ) {
  FD_LOG_ERR(( "funk crashed mid-critical-section, state unsafe" ));
  return NULL;  /* Reject corrupted state */
}
```

---

## Groove (Volume Storage Layer)

### Location

**Source:** `/home/user/firedancer/src/groove/`

### Purpose

Persistent storage abstraction with:
- Fixed 1GB volume sizes
- Bitfield metadata encoding
- Magic number validation
- Paranoid mode for extra checks

---

### Volume Structure

**File:** `fd_groove_volume.h`, Lines 52-75

```c
#define FD_GROOVE_VOLUME_FOOTPRINT (1UL<<30)  /* 1GB fixed */

struct fd_groove_volume {
  ulong magic;      /* FD_GROOVE_VOLUME_MAGIC or ~magic (empty) */
  ulong seed;       /* Random seed for hashing */

  /* Info region (metadata) */
  ulong info_off;
  ulong info_max;

  /* Data region (values) */
  ulong data_off;
  ulong data_max;

  ulong reserved[8];
};
```

**Security:**

- ✅ Fixed footprint prevents size confusion
- ✅ Magic number distinguishes valid/empty/corrupt
- ✅ Separate info and data regions
- ✅ Reserved space for future use

---

### Metadata Size Limits

**File:** `fd_groove_meta.h`, Lines 16-42

**Bitfield Structure:**

```c
struct fd_groove_meta {
  /* 64-bit bitfield */
  ulong val_sz  : 24;   /* Value size (max 16MB) */
  ulong val_max : 24;   /* Allocated size (max 16MB) */
  ulong flags   : 16;   /* Flags */
};
```

**Protection:**

```c
/* Maximum sizes */
#define FD_GROOVE_VAL_MAX ((1UL<<24)-1)  /* 16777215 bytes = 16MB */

/* Explicit bounds checking in code */
if( FD_UNLIKELY( val_sz > FD_GROOVE_VAL_MAX ) ) {
  FD_LOG_ERR(( "val_sz overflow" ));
  return NULL;
}
```

**Security:**

- ✅ 24-bit size limit (16MB per value)
- ✅ Prevents bitfield overflow
- ✅ Smaller than Funk's 28-bit limit (defense-in-depth)

---

### Key Initialization Safety

**File:** `fd_groove_base.h`, Lines 75-78

```c
static inline void
fd_groove_key_init( fd_groove_key_t * key,
                    void const *      src,
                    ulong             src_sz ) {

  /* Zero padding first */
  fd_memset( key->uc, 0, FD_GROOVE_KEY_FOOTPRINT );

  /* Then copy actual data (truncate if too large) */
  fd_memcpy( key->uc, src, fd_ulong_min( src_sz, FD_GROOVE_KEY_FOOTPRINT ) );
}
```

**Security:**

- ✅ Zero padding before copy (prevents uninitialized data)
- ✅ Truncates oversized keys (no buffer overflow)
- ✅ Safe ordering (memset before memcpy)

---

### Paranoid Mode

**File:** `fd_groove_base.h`, Lines 9-11

```c
#ifndef FD_GROOVE_PARANOID
#define FD_GROOVE_PARANOID 1  /* Enabled by default */
#endif
```

**Impact:**

When enabled, performs extra validation:
- Magic number checks on every operation
- Bounds checking on every access
- Metadata consistency verification
- Slightly slower but safer

---

## Vinyl (Index/Map Abstraction)

### Location

**Source:** `/home/user/firedancer/src/vinyl/`

### Purpose

Lock-free hash map with:
- Linear probing collision resolution
- Concurrent read support
- Probe sequence repair
- Finite termination guarantees

---

### Finite Termination Guarantee

**File:** `fd_vinyl_meta.c`, Lines 18-52

**Function:** `fd_vinyl_meta_query_fast()`

```c
int
fd_vinyl_meta_query_fast( fd_vinyl_meta_ele_t const * ele0,
                          ulong                       ele_max,
                          fd_vinyl_key_t const *      key,
                          ulong                       memo,
                          ulong *                     _ele_idx ) {

  ulong ele_idx = memo & (ele_max-1UL);
  int err = FD_VINYL_ERR_CORRUPT;

  /* FINITE TERMINATION: Loop counter prevents infinite loop */
  ulong rem;
  for( rem=ele_max; rem; rem-- ) {
    fd_vinyl_meta_ele_t const * ele = ele0 + ele_idx;

    /* Empty slot → not found */
    if( FD_UNLIKELY( !ele->phdr.ctl ) ) {
      *_ele_idx = ele_idx;
      err       = FD_VINYL_ERR_KEY;
      break;
    }

    /* Match found */
    if( FD_LIKELY( ele->memo==memo ) &&
        FD_LIKELY( fd_vinyl_key_eq( &ele->phdr.key, key ) ) ) {
      *_ele_idx = ele_idx;
      err       = FD_VINYL_SUCCESS;
      break;
    }

    /* Collision → try next slot */
    ele_idx = (ele_idx+1UL) & (ele_max-1UL);
  }

  /* Crash if loop exhausted (corruption detected) */
  FD_CRIT( rem, "corruption detected" );

  return err;
}
```

**Security Properties:**

1. **Loop Counter (`rem`)**
   - Initialized to `ele_max`
   - Decremented each iteration
   - Guarantees termination after at most `ele_max` probes

2. **Corruption Detection**
   - If loop exits with `rem==0`, table is corrupted
   - `FD_CRIT(rem, "corruption detected")` crashes process
   - Prevents silent data corruption

3. **Wraparound Safety**
   - `ele_idx = (ele_idx+1UL) & (ele_max-1UL)`
   - Assumes `ele_max` is power-of-2
   - Prevents out-of-bounds access

**Contrast with Tcache:**

This is **superior** to Tcache's implementation (`SR/IPC_Messaging.md`):
- Tcache: `for(;;)` with no iteration limit
- Vinyl: `for(rem=ele_max; rem; rem--)` with explicit limit

**Assessment:** STRONG

---

### Probe Sequence Repair

**File:** `fd_vinyl_meta.c`, Lines 119-150

**Function:** `fd_vinyl_meta_remove()`

```c
/* After removing element, repair probe sequences */

ulong probe_idx = (removed_idx + 1UL) & (ele_max-1UL);

for( ulong i=0; i<ele_max; i++ ) {
  fd_vinyl_meta_ele_t * probe = ele0 + probe_idx;

  /* Empty slot → repair complete */
  if( !probe->phdr.ctl ) break;

  /* Calculate ideal position for this element */
  ulong ideal_idx = probe->memo & (ele_max-1UL);

  /* Check if probe sequence crosses removed slot */
  ulong dist_ideal_to_removed = (removed_idx - ideal_idx) & (ele_max-1UL);
  ulong dist_ideal_to_probe   = (probe_idx - ideal_idx) & (ele_max-1UL);

  /* If removed slot is in probe range, move element back */
  if( dist_ideal_to_removed < dist_ideal_to_probe ) {
    /* Move probe element to removed slot */
    ele0[removed_idx] = *probe;

    /* Mark probe slot as removed (continue repair) */
    probe->phdr.ctl = 0;
    removed_idx = probe_idx;
  }

  probe_idx = (probe_idx + 1UL) & (ele_max-1UL);
}
```

**Security:**

- ✅ Maintains probe sequence invariant after removal
- ✅ Prevents "lost" elements (unreachable but present)
- ✅ Cyclic distance calculation handles wraparound
- ✅ Bounded iteration (terminates on first empty slot)

---

### Lock-Free Concurrent Reads

**File:** `fd_vinyl_meta.h`, Lines 125-150

**Reader-Writer Synchronization:**

```c
/* Writer updates lock range */
static inline void
fd_vinyl_meta_lock_writer( fd_vinyl_meta_t * meta,
                           ulong             lock_begin,
                           ulong             lock_end ) {

  /* Update lock atomically */
  FD_COMPILER_MFENCE();
  FD_VOLATILE( meta->lock_begin ) = lock_begin;
  FD_VOLATILE( meta->lock_end   ) = lock_end;
  FD_COMPILER_MFENCE();
}

/* Reader checks lock range */
static inline int
fd_vinyl_meta_lock_reader( fd_vinyl_meta_t const * meta,
                           ulong                   ele_idx ) {

  FD_COMPILER_MFENCE();
  ulong lock_begin = FD_VOLATILE_CONST( meta->lock_begin );
  ulong lock_end   = FD_VOLATILE_CONST( meta->lock_end );
  FD_COMPILER_MFENCE();

  /* Check if ele_idx is in locked range */
  return (ele_idx >= lock_begin) && (ele_idx < lock_end);
}
```

**Security:**

- ✅ Compiler fences prevent reordering
- ✅ Volatile access ensures actual memory reads
- ✅ Readers detect concurrent modifications
- ✅ Lock-free (readers never block)

**Limitation:**

- ⚠️ Only compiler fences, not CPU memory barriers
- On weakly-ordered architectures (ARM), may need `atomic_thread_fence()`

---

### Element State Validation

**File:** `fd_vinyl_meta.h`, Lines 38-46

**Three States:**

```c
/* Element states via phdr.ctl field:

   1. ctl == 0              → FREE (empty slot)
   2. ctl == ULONG_MAX      → CREATING (being inserted)
   3. ctl == <other value>  → ACTIVE (committed)
*/

static inline int
fd_vinyl_meta_is_free( fd_vinyl_meta_ele_t const * ele ) {
  return ele->phdr.ctl == 0UL;
}

static inline int
fd_vinyl_meta_is_creating( fd_vinyl_meta_ele_t const * ele ) {
  return ele->phdr.ctl == ULONG_MAX;
}

static inline int
fd_vinyl_meta_is_active( fd_vinyl_meta_ele_t const * ele ) {
  ulong ctl = ele->phdr.ctl;
  return (ctl != 0UL) && (ctl != ULONG_MAX);
}
```

**Security:**

- ✅ Prevents reading partially-constructed elements
- ✅ Readers skip `CREATING` elements
- ✅ State machine prevents invalid transitions
- ✅ Use-after-free detection (freed → `ctl=0`)

---

## Security Recommendations

### Immediate Actions

1. **Fix HashDoS on 32-bit** (`fd_funk_base.h:203`)
   ```c
   /* Use BLAKE3 or SipHash instead of fd_ulong_hash */
   #if !FD_HAS_INT128
   return fd_blake3_hash( key, 32, seed );
   #endif
   ```

2. **Reject Crash-State Funk** (`fd_funk.c:158`)
   ```c
   if( magic == FD_FUNK_MAGIC+1 ) {
     FD_LOG_ERR(( "corrupted state" ));
     return NULL;  /* Don't attempt recovery */
   }
   ```

### Medium Priority

3. **Add CPU Memory Barriers to Vinyl**
   - Use `atomic_thread_fence(memory_order_acquire)` for ARM
   - Ensures proper ordering on weakly-ordered architectures

4. **Document State Machine Transitions**
   - Explicit state transition diagrams
   - Clarify when each state is valid

5. **Add Integrity Checks**
   - Periodic verification of transaction tree invariants
   - Background task to validate funk/groove/vinyl consistency

---

## Testing Recommendations

### Stress Testing

1. **Funk Transaction Tree**
   - Create deep transaction hierarchies (100+ levels)
   - Attempt to create cycles
   - Verify cycle detection triggers

2. **Hash Collision Stress**
   - On 32-bit build, craft colliding keys
   - Measure lookup time degradation
   - Verify no crashes/hangs

3. **Vinyl Concurrent Access**
   - Multiple readers + single writer
   - Verify lock ranges prevent torn reads
   - Test on ARM (weak memory ordering)

### Race Condition Testing

1. **Use-After-Free Detection**
   - Free transaction while another thread accesses
   - Verify `fd_funk_txn_xid_assert()` detects race
   - Ensure crash with diagnostic message

2. **Crash-State Recovery**
   - Kill process with `magic=FD_FUNK_MAGIC+1`
   - Attempt `fd_funk_join()`
   - Verify behavior (currently continues, should reject)

3. **Probe Sequence Repair**
   - Remove elements during concurrent reads
   - Verify probe sequences remain valid
   - Ensure no lost elements

### Fuzzing Targets

1. **Funk Record Keys**
   - Fuzz 32-byte keys for hash collisions
   - Check for integer overflows in size calculations
   - Validate cycle detection

2. **Vinyl Element Insertion**
   - Fuzz memo values for hash collisions
   - Test probe sequence limits
   - Verify finite termination

---

## Positive Security Features

### Defense-in-Depth

**Multiple Layers:**
```
Funk (28-bit size limits)
  ↓
Groove (24-bit size limits)  ← Stricter
  ↓
Vinyl (finite termination)
```

Each layer enforces its own limits, preventing single-point-of-failure.

---

### Corruption Detection

**Comprehensive Checks:**

1. **Magic Numbers**
   - Funk: `FD_FUNK_MAGIC`, `FD_FUNK_MAGIC+1` (crash state)
   - Groove: `FD_GROOVE_VOLUME_MAGIC`, `~magic` (empty)

2. **Cycle Detection**
   - Transaction tree traversal with tag-based visited tracking
   - O(depth) detection, fails loudly on cycles

3. **Finite Termination**
   - Vinyl loop counter prevents infinite probes
   - `FD_CRIT` crashes on corruption instead of hanging

4. **State Validation**
   - Transaction state assertions with volatile reads
   - Element state (FREE/CREATING/ACTIVE) validation

---

### Transaction Isolation

**Copy-on-Write Semantics:**

```
Parent Transaction (TXN1)
    │
    ├─ Record A (value = "foo")
    │
    └─ Child Transaction (TXN2)
           │
           ├─ Reads Record A → sees "foo"
           │
           ├─ Modifies Record A → creates copy
           │  - New record in TXN2 namespace
           │  - Parent record unchanged
           │
           └─ Commit → atomically publish changes
              - CAS state: ACTIVE → PUBLISH
              - Memory fence before visibility
```

**Properties:**
- ✅ Parent never sees child's uncommitted changes
- ✅ Child sees parent's committed state
- ✅ Atomic commit (all-or-nothing)
- ✅ Rollback is instant (just cancel transaction)

---

## References

- Source: `/home/user/firedancer/src/funk/`, `/src/groove/`, `/src/vinyl/`
- Related: `SR/Architecture.md`, `SR/IPC_Messaging.md`, `SR/Memory_Safety.md`
- xxHash3: [https://github.com/Cyan4973/xxHash](https://github.com/Cyan4973/xxHash)

**END OF STATE MANAGEMENT ANALYSIS**
