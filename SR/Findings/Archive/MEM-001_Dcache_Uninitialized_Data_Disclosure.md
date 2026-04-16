# MEDIUM: Dcache Data Region Uninitialized Memory Disclosure

**CVE**: TBD
**Severity**: Medium
**Component**: Tango IPC - Dcache
**Location**: `src/tango/dcache/fd_dcache.c:70-84`
**Affected Versions**: Current Firedancer main branch

## Summary

The dcache initialization function (`fd_dcache_new`) zeros the header and application regions but fails to zero the data region, leaving potentially sensitive information from previous memory allocations accessible to dcache users.

## Technical Details

The `fd_dcache_new()` function at lines 70-84 performs partial memory initialization:

```c
fd_memset( shmem, 0, sizeof(fd_dcache_private_hdr_t) );  // Line 70: Zero header only

fd_dcache_private_hdr_t * hdr = (fd_dcache_private_hdr_t *)shmem;

hdr->data_sz = data_sz;
hdr->app_sz  = app_sz;
hdr->app_off = sizeof(fd_dcache_private_hdr_t) + fd_ulong_align_up( data_sz, FD_DCACHE_ALIGN );

fd_memset( (uchar*)shmem+hdr->app_off, 0, app_sz );  // Line 78: Zero app region only
```

The memory layout is:
```
+----------------+
| Header (zero'd)|  <- Cleared at line 70
+----------------+
| Guard Region   |  <- 3968 bytes
+----------------+
| Data Region    |  <- NOT CLEARED - VULNERABILITY
| (data_sz bytes)|
+----------------+
| App Region     |  <- Cleared at line 78
+----------------+
```

The data region, which stores actual packet/transaction payloads, is never zeroed during initialization. This means:

1. When a dcache is first allocated, the data region contains whatever was previously in that memory
2. When a chunk is allocated but not immediately written to, it contains stale data
3. Consumers reading from dcache chunks before producers write to them will see uninitialized memory

## Proof of Concept

```c
#include "fd_dcache.h"

void test_dcache_info_leak(void) {
  // Step 1: Allocate memory and fill with sensitive data
  ulong data_sz = 1UL << 30;  // 1GB
  ulong app_sz = 4096;
  void * mem = malloc( fd_dcache_footprint( data_sz, app_sz ) );

  // Simulate sensitive data in memory (e.g., from previous allocation)
  memset( mem, 0x41, fd_dcache_footprint( data_sz, app_sz ) );

  // Step 2: Initialize dcache (partial zeroing)
  void * dcache = fd_dcache_new( mem, data_sz, app_sz, 0 );

  // Step 3: Read from data region WITHOUT writing first
  uchar * data_region = (uchar*)dcache + sizeof(fd_dcache_private_hdr_t) + 3968;

  // Step 4: Observe uninitialized data
  for( ulong i=0; i<100; i++ ) {
    printf( "%02x ", data_region[i] );  // Will print "41 41 41..." - leaked data!
  }
}
```

## Impact

**Information Disclosure (MEDIUM severity)**:

1. **Cross-tile information leakage**: If one tile deallocates dcache and another tile allocates the same memory, sensitive data can leak between tiles

2. **Transaction content exposure**: Unwritten chunks may expose fragments of previous transactions to subsequent consumers

3. **Timing-based reconnaissance**: Attacker can craft transactions that trigger reads from uninitialized chunks to extract memory contents

4. **Limited exploitability**:
   - Requires attacker to control timing of chunk allocation/deallocation
   - Memory contains data from same process (sandboxed), not arbitrary kernel memory
   - Sandboxing limits impact to same validator instance

## Remediation

Add explicit zeroing of the data region in `fd_dcache_new()`:

```c
fd_memset( shmem, 0, sizeof(fd_dcache_private_hdr_t) );

fd_dcache_private_hdr_t * hdr = (fd_dcache_private_hdr_t *)shmem;

hdr->data_sz = data_sz;
hdr->app_sz  = app_sz;
hdr->app_off = sizeof(fd_dcache_private_hdr_t) + fd_ulong_align_up( data_sz, FD_DCACHE_ALIGN );

// FIX: Zero the data region
ulong data_off = sizeof(fd_dcache_private_hdr_t);
fd_memset( (uchar*)shmem + data_off, 0, fd_ulong_align_up( data_sz, FD_DCACHE_ALIGN ) );

fd_memset( (uchar*)shmem+hdr->app_off, 0, app_sz );
```

**Performance consideration**: Zeroing 1GB on initialization may impact startup time. Alternative mitigations:
- Zero chunks on allocation (in `fd_dcache_compact_next()`)
- Use `madvise(MADV_DONTNEED)` to have kernel zero pages lazily
- Document that consumers must not read before writing

## References

- Dcache implementation: `src/tango/dcache/fd_dcache.c`
- Dcache header: `src/tango/dcache/fd_dcache.h`
- Related: CWE-908 (Use of Uninitialized Resource)
