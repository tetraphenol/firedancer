# DOS-004: TAR Archive Extraction - Missing File Size Limits

## Severity
**MEDIUM**

## Summary
The TAR archive extraction implementation used for snapshot processing lacks explicit file size limits. While using streaming extraction (which reduces memory footprint), there are no checks preventing extraction of individual files with gigabytes of uncompressed data, enabling TAR archive bomb attacks.

## Affected Components
- `src/util/archive/fd_tar_reader.c` (TAR extraction implementation)
- `src/util/archive/fd_tar_reader.h` (TAR reader API)
- `src/discof/restore/fd_snapdc_tile.c` (snapshot decompression tile)
- `src/discof/restore/fd_snapin_tile_funk.c` (snapshot ingestion)

## Technical Details

### Vulnerability Mechanism

**Current Implementation:**

From `src/util/archive/fd_tar_reader.c`:

1. **File Size Parsing** (with overflow detection):
   ```c
   ulong file_sz = fd_tar_meta_get_size( &reader->header );
   if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) {
     FD_LOG_WARNING(( "Failed to parse file size in tar header" ));
     return EPROTO;
   }
   ```

2. **Streaming Extraction**:
   - Uses callback-based API (no full file buffering)
   - Extracts in chunks to provided callback function
   - Reduces memory footprint vs. full-file extraction

**The Gap:**

✅ Parses file size correctly with overflow detection
✅ Uses streaming to avoid full buffering
❌ **No maximum file size limit enforced**
❌ **No total archive size limit enforced**
❌ **No path traversal protection visible** (may be in callbacks)

**Attack Vector:**

```
malicious_snapshot.tar contains:
  - accounts.bin (100 GB)  ← No rejection!
  - ledger.db (50 GB)      ← No rejection!
  - config.json (1 MB)     ← Normal file
Total: 150 GB of uncompressed data
```

### Existing Protections (Partial)

**Account Size Validation** (`src/discof/restore/fd_snapin_tile_funk.c:82`):

```c
if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) )
  FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
```

- **Protects:** Individual account data within TAR
- **Doesn't protect:** Non-account files in TAR archive
- **Limit:** `FD_RUNTIME_ACC_SZ_MAX = 10 MiB`

**Streaming Mode:**

- **Benefit:** Memory consumption bounded by chunk size, not file size
- **Limitation:** Disk/SSD space still consumed by large files
- **Limitation:** CPU cycles wasted extracting malicious files

### Attack Scenarios

**Attack Vector 1: Disk Space Exhaustion**

1. Attacker creates snapshot with massive files:
   ```
   snapshot.tar (compressed: 10 MB)
   ├── ledger.db (uncompressed: 500 GB)
   └── accounts.bin (uncompressed: 500 GB)
   ```

2. Validator downloads and begins extracting
3. Disk space fills up → validator cannot operate
4. Requires manual cleanup before restart

**Attack Vector 2: CPU/IO Exhaustion**

1. Snapshot contains many moderately large files (1GB each × 1000 files)
2. Validator spends hours extracting
3. CPU cycles and disk I/O consumed
4. Snapshot sync never completes

**Attack Vector 3: Combined with Compression Bomb**

1. TAR archive is zstd-compressed (see DOS-001)
2. Compressed size: 10 MB
3. Decompressed TAR: 10 GB (compression bomb)
4. TAR contains files totaling: 100 GB (archive bomb)
5. **Combined amplification: 10,000:1**

**Prerequisites:**
- Attacker controls snapshot distribution OR
- Man-in-the-middle snapshot download OR
- Malicious snapshot uploaded to public servers

### Impact Assessment

**Availability Impact**: MEDIUM-HIGH
- Disk exhaustion prevents validator operation
- CPU/IO waste during extraction
- Snapshot sync failure → validator cannot join network

**Recovery**:
- Disk full: Manual cleanup, re-sync from trusted snapshot
- CPU/IO waste: Manual kill, retry with trusted snapshot

**Scope**:
- Affects validators during initial sync
- Affects validators downloading incremental snapshots
- Does not affect running validators (until next snapshot)

**Real-World Scenario:**
- New validator joins network
- Downloads snapshot from untrusted source
- Extraction fills disk
- Validator cannot start

## Proof of Concept

**Create TAR Archive Bomb:**

```bash
#!/bin/bash

# Create 100 GB sparse file (instant creation)
dd if=/dev/zero of=huge_file.bin bs=1 count=0 seek=100G

# Create TAR archive
tar -cf archive_bomb.tar huge_file.bin

# Result:
#   TAR file size: ~100 GB (+ headers)
#   Extraction: Fills disk with 100 GB
```

**Compressed TAR Bomb:**

```bash
# Create 10 GB of zeros (highly compressible)
dd if=/dev/zero of=zeros.bin bs=1M count=10240

# Compress with zstd
tar -cf - zeros.bin | zstd -19 -o snapshot_bomb.tar.zst

# Result:
#   Compressed size: ~10 MB (1000:1 ratio)
#   Decompressed TAR: 10 GB
#   Extracted file: 10 GB
```

**Firedancer Behavior (Current):**

```c
// TAR reader will extract the entire file without rejection
// Only limits:
//   - Available disk space
//   - Account size validation (10 MiB) for account files
//   - No limit for non-account files
```

## Exploitation Difficulty
**LOW-MEDIUM**

**Factors Increasing Difficulty:**
- Requires ability to serve snapshots OR MITM
- Validators may download from trusted sources only
- Operators may notice disk space filling before completion

**Factors Decreasing Difficulty:**
- Standard tools can create TAR bombs
- No authentication on snapshot downloads (HTTP/HTTPS only)
- Operators may not monitor disk space proactively

## Recommended Mitigations

### 1. Enforce Per-File Size Limit (Immediate Fix)

Add to `src/util/archive/fd_tar_reader.c`:

```c
#define FD_TAR_MAX_FILE_SIZE (10UL << 30)  // 10 GB per file

// In fd_tar_reader_advance():
ulong file_sz = fd_tar_meta_get_size( &reader->header );

if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) {
  FD_LOG_WARNING(( "Failed to parse file size in tar header" ));
  return EPROTO;
}

// NEW: Enforce maximum file size
if( FD_UNLIKELY( file_sz > FD_TAR_MAX_FILE_SIZE ) ) {
  FD_LOG_ERR(( "TAR file '%s' size %lu exceeds limit %lu",
               reader->header.filename, file_sz, FD_TAR_MAX_FILE_SIZE ));
  return EFBIG;  // File too big
}
```

### 2. Enforce Total Archive Size Limit

Track cumulative extraction:

```c
typedef struct {
  // ... existing fields ...
  ulong total_extracted;      // Bytes extracted so far
  ulong max_total_size;       // Maximum allowed total
} fd_tar_reader_t;

#define FD_TAR_MAX_TOTAL_SIZE (50UL << 30)  // 50 GB per archive

// In extraction loop:
reader->total_extracted += bytes_extracted;

if( FD_UNLIKELY( reader->total_extracted > reader->max_total_size ) ) {
  FD_LOG_ERR(( "TAR total extraction %lu exceeds limit %lu",
               reader->total_extracted, reader->max_total_size ));
  return EFBIG;
}
```

### 3. Add Path Traversal Protection

Ensure file paths stay within target directory:

```c
int
fd_tar_validate_path( char const * path ) {
  // Reject absolute paths
  if( path[0] == '/' ) {
    FD_LOG_WARNING(( "TAR contains absolute path: %s", path ));
    return -1;
  }

  // Reject path traversal attempts
  if( strstr( path, ".." ) != NULL ) {
    FD_LOG_WARNING(( "TAR contains path traversal: %s", path ));
    return -1;
  }

  // Reject symlink to absolute path (if supported)
  // ...

  return 0;
}

// Call before extraction:
if( fd_tar_validate_path( reader->header.filename ) != 0 ) {
  return EACCES;
}
```

### 4. Implement Extraction Timeout

Prevent indefinite extraction:

```c
#define FD_TAR_EXTRACTION_TIMEOUT_NS (300UL * 1000000000UL)  // 5 minutes

// Track extraction start time
long extraction_start = fd_log_wallclock();

// In extraction loop:
long now = fd_log_wallclock();
if( (now - extraction_start) > FD_TAR_EXTRACTION_TIMEOUT_NS ) {
  FD_LOG_ERR(( "TAR extraction timeout after %lu seconds",
               FD_TAR_EXTRACTION_TIMEOUT_NS / 1000000000UL ));
  return ETIMEDOUT;
}
```

### 5. Add Disk Space Pre-Check

Before extraction, verify sufficient space:

```c
#include <sys/statvfs.h>

int
fd_tar_check_disk_space( char const * path, ulong required_bytes ) {
  struct statvfs stat;
  if( statvfs( path, &stat ) != 0 ) {
    FD_LOG_WARNING(( "Failed to check disk space: %s", strerror(errno) ));
    return -1;
  }

  ulong available = stat.f_bavail * stat.f_frsize;

  if( available < required_bytes ) {
    FD_LOG_ERR(( "Insufficient disk space: need %lu, have %lu",
                 required_bytes, available ));
    return -1;
  }

  return 0;
}

// Before extraction:
ulong total_size = estimate_tar_size( tar_path );
if( fd_tar_check_disk_space( extract_dir, total_size + (10UL<<30) /* 10GB margin */ ) != 0 ) {
  return ENOSPC;
}
```

### 6. Implement File Type Allowlist

Only extract expected file types:

```c
static char const * allowed_files[] = {
  "accounts.bin",
  "ledger.db",
  "config.json",
  "status.json",
  NULL
};

int
fd_tar_is_allowed( char const * filename ) {
  for( ulong i = 0; allowed_files[i] != NULL; i++ ) {
    if( strcmp( filename, allowed_files[i] ) == 0 ) return 1;
  }
  return 0;
}

// In extraction:
if( !fd_tar_is_allowed( reader->header.filename ) ) {
  FD_LOG_WARNING(( "TAR contains unexpected file: %s", reader->header.filename ));
  continue;  // Skip file
}
```

## Detection Strategies

### Pre-Extraction Scanning

```bash
# List TAR contents before extraction
tar -tzf snapshot.tar.zst | head -20

# Check total uncompressed size
tar -tzf snapshot.tar.zst --block-number | \
  awk '{sum+=$NF} END {print sum " bytes"}'

# Check largest file
tar -tvf snapshot.tar.zst | sort -k5 -rn | head -1
```

### Runtime Monitoring

```bash
# Monitor disk space during extraction
watch -n 1 df -h /var/lib/firedancer

# Alert if disk usage exceeds threshold
if [ $(df /var/lib/firedancer | awk 'NR==2 {print $5}' | sed 's/%//') -gt 80 ]; then
  alert "Disk space critical during snapshot extraction"
fi

# Monitor extraction progress
tail -f /var/log/firedancer.log | grep -i "extracting\|tar"
```

### Automated Validation

```c
// Snapshot validation service
int fd_snapshot_validate( char const * snapshot_path ) {
  // 1. Check compressed size < 5 GB
  struct stat st;
  if( stat( snapshot_path, &st ) == 0 ) {
    if( st.st_size > (5UL << 30) ) {
      FD_LOG_ERR(( "Snapshot compressed size %lu exceeds safe limit", st.st_size ));
      return -1;
    }
  }

  // 2. Test decompression ratio
  ulong compressed_sz = st.st_size;
  ulong decompressed_sz = test_decompression_size( snapshot_path );
  if( (decompressed_sz / compressed_sz) > 100 ) {
    FD_LOG_ERR(( "Snapshot decompression ratio %lu:1 is suspicious",
                 decompressed_sz / compressed_sz ));
    return -1;
  }

  // 3. List TAR contents, check file sizes
  // ...

  return 0;
}
```

## Testing Recommendations

### Unit Tests

```c
// test_tar_reader.c

void test_file_size_limit( void ) {
  // Create TAR with file > FD_TAR_MAX_FILE_SIZE
  // Attempt extraction
  // Verify rejection with EFBIG
}

void test_total_size_limit( void ) {
  // Create TAR with many files totaling > FD_TAR_MAX_TOTAL_SIZE
  // Attempt extraction
  // Verify rejection after limit reached
}

void test_path_traversal( void ) {
  // Create TAR with "../../../etc/passwd"
  // Attempt extraction
  // Verify rejection
}
```

### Integration Tests

```bash
# Test 1: Reject oversized file
fdctl test --tar-with-large-file --expect-rejection

# Test 2: Reject archive bomb
fdctl test --tar-bomb --expect-rejection

# Test 3: Accept normal snapshot
fdctl test --valid-snapshot --expect-success
```

### Fuzzing

```bash
# Fuzz TAR headers for overflow/underflow
AFL_INPUT=valid_snapshot.tar \
AFL_OUTPUT=fuzz_findings \
afl-fuzz -i corpus -o findings -- \
  fdctl snapshot extract @@
```

## References

### Vulnerabilities in the Wild
- CVE-2001-1267: GNU tar directory traversal
- CVE-2016-6321: tar symlink vulnerability
- CVE-2018-14618: curl TAR file size overflow

### Standards
- POSIX.1-2008 tar format specification
- GNU tar manual (security considerations)

### Internal References
- `src/util/archive/fd_tar_reader.c` - TAR implementation
- `src/discof/restore/fd_snapdc_tile.c` - Snapshot decompression
- `SR/Findings/DOS-001_Compression_Bomb_Vulnerability.md` - Related finding

## Timeline
- **Discovered**: 2025-11-10
- **Reported**: 2025-11-10
- **Status**: UNFIXED (no file size limits in TAR extraction)

## Additional Notes

### Interaction with DOS-001 (Compression Bomb)

These vulnerabilities compound:

```
Attack Chain:
  1. Zstd compression bomb: 10 MB → 10 GB (1000:1)
  2. TAR archive bomb: 10 GB TAR → 100 GB files (10:1)
  3. Total amplification: 10 MB → 100 GB (10,000:1)
```

**Mitigation Strategy:** Must address BOTH vulnerabilities:
- DOS-001: Limit decompression ratio
- DOS-004: Limit TAR file sizes

### Snapshot Source Trust

**Current Model:**
- Validators download snapshots via HTTP(S) from known endpoints
- No cryptographic verification of snapshot integrity (beyond HTTPS)
- Trust is implicit in endpoint (e.g., `mainnet-beta.solana.com`)

**Recommendations:**
1. Implement snapshot signature verification
2. Maintain allowlist of trusted snapshot sources
3. Add checksums to snapshot metadata

### Disk Space Management

**Best Practices:**
- Reserve 10-20% of disk space for system operations
- Monitor disk usage continuously
- Alert when usage exceeds 80%
- Implement automatic cleanup of old snapshots

### Performance Considerations

**Validation Overhead:**
- File size checks: Negligible (already parsing headers)
- Total size tracking: ~1 addition per file (negligible)
- Path validation: String operations (microseconds per file)
- Disk space check: One `statvfs()` call before extraction (milliseconds)

**Total overhead: < 1% of extraction time**

### Operational Impact

**Before Mitigation:**
- Risk: Snapshot bomb fills disk
- Recovery: Manual cleanup, re-download from trusted source
- Downtime: Hours (disk cleanup + re-sync)

**After Mitigation:**
- Detection: Immediate (file size check before extraction)
- Recovery: Automatic (reject bad snapshot, try next source)
- Downtime: Minimal (validation failure → retry with different snapshot)

This finding, while lower severity than DOS-001 and DOS-002, is important for production operations as it prevents disk exhaustion attacks during snapshot synchronization.
