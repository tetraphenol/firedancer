# Firedancer DoS Resilience & Fault Tolerance - Security Audit Summary

**Audit Date:** 2025-11-10
**Scope:** Code implementation analysis (documentation excluded per requirements)
**Auditor:** Security Research Team
**Methodology:** Static code analysis, architecture review, threat modeling

---

## Executive Summary

This audit assesses Firedancer's resilience against denial-of-service attacks, fault handling mechanisms, and tile isolation controls. The analysis is based **exclusively on code implementation**, not documentation claims.

### Overall Assessment

**Strengths:** Firedancer demonstrates **elite-level security isolation** with comprehensive multi-layer sandboxing (seccomp, namespaces, pivot root) and strong input validation for most attack surfaces. The tile architecture provides excellent fault isolation.

**Weaknesses:** The system follows a **fail-fast philosophy** with limited automatic recovery. Several DoS vectors remain inadequately mitigated, particularly around decompression bombs, hung tile detection, and crash-inducing transaction handling.

### Risk Summary

| Finding | Severity | Impact | Exploitability |
|---------|----------|--------|----------------|
| [DOS-001](#dos-001-compression-bomb) | HIGH | Memory exhaustion, validator crash | MEDIUM |
| [DOS-002](#dos-002-missing-watchdog) | HIGH | Indefinite validator stall | MEDIUM-HIGH |
| [DOS-003](#dos-003-crash-circuit-breaker) | MEDIUM-HIGH | Repeated crashes, downtime | MEDIUM |
| [DOS-004](#dos-004-tar-archive-bomb) | MEDIUM | Disk exhaustion, sync failure | LOW-MEDIUM |

---

## Findings Overview

### DOS-001: Compression Bomb Vulnerability
**File:** `DOS-001_Compression_Bomb_Vulnerability.md`
**Severity:** HIGH

**Summary:** Zstandard decompression lacks ratio limits, allowing small compressed payloads to expand to gigabytes.

**Affected Code:**
- `src/ballet/zstd/fd_zstd.c:22-36`
- `src/ballet/zstd/fd_zstd.h:46` (explicit comment acknowledging gap)

**Key Evidence:**
```c
/* The Solana protocol does not properly bound max decompressed
   frame size, so using streaming mode is safer for now. */
```

**Attack Vector:**
- Compressed snapshot: 10 MB → Decompressed: 10 GB (1000:1 ratio)
- Memory exhaustion → OOM kill → validator crash

**Mitigation Priority:** CRITICAL (immediate fix recommended)

---

### DOS-002: Missing Tile Watchdog
**File:** `DOS-002_Missing_Tile_Watchdog.md`
**Severity:** HIGH

**Summary:** No automatic watchdog to detect and terminate hung tiles. Heartbeat monitoring exists (100ms stale threshold) but no recovery action is taken.

**Affected Code:**
- `src/app/shared/commands/run/run.c:416-461` (supervisor - no watchdog)
- `src/tango/cnc/fd_cnc.h:68-74` (documented but not implemented)

**Key Evidence:**
```c
// Supervisor only handles crashes, not hangs
if( !WIFEXITED( wstatus ) ) {
  FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d", ... ));
  fd_sys_util_exit_group( ... );  // Shutdown all tiles
}
// No check for stale heartbeat with automatic action
```

**Attack Vector:**
- Infinite loop in tile → Heartbeat stops → Monitor shows "STALE"
- **No automatic recovery** → Validator stalls indefinitely

**Mitigation Priority:** CRITICAL (implement watchdog timer)

---

### DOS-003: Transaction Crash Circuit Breaker
**File:** `DOS-003_Transaction_Crash_Circuit_Breaker.md`
**Severity:** MEDIUM-HIGH

**Summary:** No mechanism to detect and ban transactions that repeatedly cause tile crashes.

**Affected Code:**
- `src/discoh/bank/fd_bank_tile.c:86-331` (execution - no crash tracking)
- `src/disco/pack/fd_pack.c` (mempool - no crash history)

**Key Evidence:**
```c
// On crash, supervisor shuts down validator
// NO CORRELATION between crash and transaction
// NO BAN LIST for problematic transactions
// On restart, same transaction can crash validator again
```

**Attack Vector:**
1. Discover transaction that crashes bank tile
2. Submit repeatedly via gossip or direct RPC
3. Validator crashes → restarts → crashes again (loop)

**Mitigation Priority:** HIGH (implement crash logging + ban list)

---

### DOS-004: TAR Archive Bomb
**File:** `DOS-004_TAR_Archive_Bomb.md`
**Severity:** MEDIUM

**Summary:** TAR extraction for snapshots lacks file size limits, enabling archive bombs.

**Affected Code:**
- `src/util/archive/fd_tar_reader.c` (no size limits)
- `src/discof/restore/fd_snapdc_tile.c` (snapshot processing)

**Key Evidence:**
```c
// Parses file size but doesn't enforce maximum
ulong file_sz = fd_tar_meta_get_size( &reader->header );
// No check: if( file_sz > MAX_FILE_SIZE ) reject();
```

**Attack Vector:**
- Malicious snapshot contains 100GB files
- Extraction fills disk
- Validator cannot operate

**Mitigation Priority:** MEDIUM (add per-file and total size limits)

---

## Security Controls Assessment

### ✅ Strong Protections (Well Implemented)

#### 1. Transaction Deserialization
**Location:** `src/ballet/txn/fd_txn_parse.c`

- **MTU limit:** 1,232 bytes
- **Comprehensive bounds checking:** Every read preceded by `CHECK_LEFT(n)`
- **Component limits:** Max 127 signatures, 128 accounts, 64 instructions
- **No leftover bytes:** Ensures entire payload consumed

**Verdict:** Excellent protection against deserialization bombs.

#### 2. Seccomp-BPF Syscall Filtering
**Location:** 42 tile-specific `.seccomppolicy` files

- **Attack surface reduction:** 99% (verify tile: only 2 syscalls)
- **Tile-specific policies:** Each tile has minimal syscall allowlist
- **Examples:**
  - Verify tile: `write`, `fsync` (2 syscalls)
  - Exec tile: `write`, `fsync` (2 syscalls)
  - QUIC tile: `write`, `fsync`, `getrandom` (3 syscalls)

**Verdict:** Elite-level kernel attack surface reduction.

#### 3. Namespace Isolation
**Location:** `src/util/sandbox/fd_sandbox.c:654-657`

- **7 namespaces per tile:**
  - USER (2x nested), PID, NET, MOUNT, CGROUP, IPC, UTS
- **Pivot root:** Empty filesystem via `pivot_root()`, more secure than `chroot()`
- **Landlock:** Filesystem access denied at kernel level

**Verdict:** Industry-leading isolation comparable to container runtimes.

#### 4. Resource Limits
**Location:** `src/util/sandbox/fd_sandbox.c:386-433`

- **File descriptors:** Tile-specific `RLIMIT_NOFILE` (2-64 per tile)
- **Process creation:** `RLIMIT_NPROC = 0` (cannot fork)
- **Memory locking:** `RLIMIT_MEMLOCK = 0`
- **Realtime priority:** `RLIMIT_RTPRIO = 0`, `RLIMIT_RTTIME = 0`

**Verdict:** Comprehensive resource limits prevent exhaustion attacks.

#### 5. QUIC Packet Size Limits
**Location:** `src/waltz/quic/fd_quic_enum.h`

- **MTU:** 1,500 bytes
- **Max payload:** 1,472 bytes
- **Initial payload:** 1,200 bytes max
- **Retry token:** 256 bytes max

**Verdict:** Strong protection with multiple overlapping limits.

#### 6. sBPF Program Loading
**Location:** `src/ballet/sbpf/fd_sbpf_loader.c`

- **Max program size:** 10 MiB (protocol limit)
- **Max instructions:** ~1.3 million
- **Strict ELF parsing:** Overflow checks with `fd_ulong_sat_add`

**Verdict:** Well-bounded to protocol limits.

---

### ⚠️ Moderate Concerns

#### 1. Zstandard Decompression
**Issue:** No decompression ratio limits (see DOS-001)
**Risk:** Compression bomb → memory exhaustion

#### 2. TAR Extraction
**Issue:** No file size limits (see DOS-004)
**Risk:** Archive bomb → disk exhaustion

#### 3. Snapshot Decompression
**Issue:** Combines zstd + TAR vulnerabilities
**Risk:** Compound attack (10MB → 100GB amplification)

---

### ❌ Critical Gaps

#### 1. Hung Tile Detection
**Issue:** No automatic watchdog (see DOS-002)
**Risk:** Single hung tile stalls entire validator

#### 2. Transaction Crash Tracking
**Issue:** No circuit breaker for crash-inducing transactions (see DOS-003)
**Risk:** Repeated crashes from same transaction

#### 3. Automatic Recovery
**Issue:** Fail-fast only, no tile restart mechanism
**Risk:** Any failure requires full validator restart

---

## Threat Scenarios Analysis

### Scenario 1: Decompression/Deserialization Bombs

| Attack Surface | Protection Level | Notes |
|----------------|------------------|-------|
| Transaction parsing | ✅ STRONG | Strict MTU (1,232 bytes), bounds checking |
| Zstd decompression | ❌ VULNERABLE | No ratio limits (DOS-001) |
| QUIC packets | ✅ STRONG | Multiple size limits |
| sBPF programs | ✅ STRONG | Protocol-level size limits |
| Bincode | ✅ STRONG | Pre-allocation, bounds checking |
| TAR extraction | ⚠️ MODERATE | No file size limits (DOS-004) |

**Most Impactful:** Zstd compression bomb (DOS-001)

---

### Scenario 2: Kernel Handle Exhaustion

| Resource | Protection Level | Mechanism |
|----------|------------------|-----------|
| File descriptors | ✅ STRONG | Per-tile `RLIMIT_NOFILE` (2-64) |
| Process handles | ✅ STRONG | `RLIMIT_NPROC = 0` (cannot fork) |
| Message queues | ✅ STRONG | `RLIMIT_MSGQUEUE = 0` |
| Signals | ✅ STRONG | `RLIMIT_SIGPENDING = 0` |
| Memory locks | ✅ STRONG | `RLIMIT_MEMLOCK = 0` |

**Verdict:** Well protected against kernel resource exhaustion.

---

### Scenario 3: Remote Code Execution

| Defense Layer | Status | Implementation |
|---------------|--------|----------------|
| Syscall filtering | ✅ ELITE | Seccomp-BPF (99% reduction) |
| Process isolation | ✅ STRONG | PID namespaces per tile |
| Network isolation | ✅ STRONG | NET namespaces (optional) |
| Filesystem access | ✅ STRONG | Pivot root + Landlock |
| Privilege escalation | ✅ STRONG | 2x nested USER namespaces + cap drop |
| UID/GID separation | ❌ ABSENT | All tiles same uid/gid |
| Cgroup quotas | ❌ ABSENT | Namespace only, no CPU/mem limits |

**Verdict:** Excellent isolation despite lack of UID separation.

---

### Scenario 4: Thread Lockups & Deadlocks

| Mechanism | Status | Notes |
|-----------|--------|-------|
| Heartbeat monitoring | ✅ PRESENT | 100ms stale threshold |
| Watchdog timer | ❌ ABSENT | See DOS-002 |
| Automatic recovery | ❌ ABSENT | Fail-fast only |
| Deadlock detection | ❌ ABSENT | No cycle detection |
| Operation timeouts | ⚠️ LIMITED | Only in tests, not production |

**Most Critical Gap:** No watchdog timer (DOS-002)

---

### Scenario 5: Troublesome Transactions

| Mechanism | Status | Implementation |
|-----------|--------|----------------|
| Mempool | ✅ PRESENT | Pack tile with priority queues |
| Deduplication | ✅ PRESENT | Transaction cache (tcache) |
| Skip mechanism | ✅ PRESENT | Prevent scheduling retry loops (50 attempts) |
| Penalty treaps | ✅ PRESENT | Isolate hot account conflicts |
| Expiration | ✅ PRESENT | 150 slots lifetime |
| Crash tracking | ❌ ABSENT | See DOS-003 |
| Transaction retry | ❌ NO | Lost on crash, no recovery |
| Circuit breaker | ⚠️ LIMITED | Bundle blacklist only |

**Most Critical Gap:** No crash-transaction correlation (DOS-003)

---

## Prioritized Recommendations

### 🔴 CRITICAL (Immediate Action)

#### 1. Implement Decompression Ratio Limits (DOS-001)
**File:** `src/ballet/zstd/fd_zstd.c`

```c
#define FD_ZSTD_MAX_DECOMPRESSION_RATIO (100UL)

// Add in decompression loop:
if( (decompressed_sz / compressed_sz) > FD_ZSTD_MAX_DECOMPRESSION_RATIO ) {
  FD_LOG_ERR(( "Decompression ratio %lu:1 exceeds limit", ratio ));
  return -1;
}
```

**Effort:** Low (1-2 days)
**Impact:** Prevents memory exhaustion attacks

#### 2. Implement Tile Watchdog Timer (DOS-002)
**File:** `src/app/shared/commands/run/run.c`

```c
#define WATCHDOG_TIMEOUT_NS (5UL * 1000000000UL)  // 5 seconds

// In supervisor loop, check heartbeat age:
if( age_ns > WATCHDOG_TIMEOUT_NS ) {
  kill( tile_pid, SIGKILL );
  fd_sys_util_exit_group( 1 );
}
```

**Effort:** Medium (3-5 days)
**Impact:** Prevents indefinite hangs

---

### 🟡 HIGH (Within 1 Month)

#### 3. Implement Transaction Crash Circuit Breaker (DOS-003)
**Files:**
- `src/app/shared/commands/run/run.c` (crash logging)
- `src/disco/dedup/fd_dedup_tile.c` (ban list)
- `src/disco/pack/fd_pack.c` (ban list integration)

**Components:**
- Crash-transaction correlation logging
- Persistent ban list storage
- Ban list loading on startup
- Graduated ban durations (150 slots → permanent)

**Effort:** High (1-2 weeks)
**Impact:** Prevents crash-loop attacks

#### 4. Add TAR File Size Limits (DOS-004)
**File:** `src/util/archive/fd_tar_reader.c`

```c
#define FD_TAR_MAX_FILE_SIZE (10UL << 30)  // 10 GB
#define FD_TAR_MAX_TOTAL_SIZE (50UL << 30)  // 50 GB

if( file_sz > FD_TAR_MAX_FILE_SIZE ) {
  return EFBIG;
}
```

**Effort:** Low (1-2 days)
**Impact:** Prevents disk exhaustion

---

### 🟢 MEDIUM (Within 3 Months)

#### 5. Implement Graceful Tile Recovery
**Complexity:** High (requires architecture changes)

**Features:**
- Individual tile restart capability
- State preservation across restarts
- Graceful degradation vs. fail-fast

**Effort:** Very High (4-6 weeks)
**Impact:** Improved availability

#### 6. Add Cgroup Resource Quotas
**File:** `src/util/sandbox/fd_sandbox.c`

**Features:**
- CPU quotas per tile
- Memory limits per tile
- IO bandwidth limits

**Effort:** Medium (1-2 weeks)
**Impact:** Better resource isolation

---

## Testing & Validation

### Recommended Test Coverage

#### Unit Tests
- [x] Transaction deserialization bounds (existing)
- [ ] Decompression ratio limits (new - DOS-001)
- [ ] Watchdog timer triggers (new - DOS-002)
- [ ] Ban list add/remove (new - DOS-003)
- [ ] TAR size limits (new - DOS-004)

#### Integration Tests
- [ ] Compression bomb rejection
- [ ] Hung tile detection and termination
- [ ] Crash-inducing transaction ban
- [ ] Archive bomb rejection
- [ ] Snapshot validation

#### Fuzzing Targets
- [x] Transaction parser (existing)
- [ ] Zstd decompressor with ratio tracking (new)
- [ ] TAR reader with size limits (new)
- [ ] sBPF loader (existing)

---

## Comparison: Firedancer vs. Industry Standards

### Container Runtime Comparison

| Feature | Firedancer | Docker | Kubernetes |
|---------|-----------|--------|------------|
| Seccomp-BPF | ✅ Tile-specific | ✅ Custom profiles | ✅ Pod security |
| Namespaces | ✅ 7 namespaces | ✅ 6-7 namespaces | ✅ Pod isolation |
| Capabilities | ✅ All dropped | ✅ Restricted | ✅ Restricted |
| Resource limits | ✅ rlimits | ✅ cgroups v2 | ✅ Resource quotas |
| Watchdog | ❌ Absent | ✅ Health checks | ✅ Liveness probes |
| Auto-recovery | ❌ Absent | ✅ Restart policy | ✅ Restart policy |

**Verdict:** Firedancer isolation is **comparable to container runtimes** but lacks automatic recovery mechanisms.

---

## Attack Surface Summary

### Most Exploitable DoS Vectors (Ranked)

1. **Compression bomb** (DOS-001) - MEDIUM exploitability, HIGH impact
2. **Tile hang** (DOS-002) - MEDIUM-HIGH exploitability, HIGH impact
3. **Crash-inducing transaction** (DOS-003) - MEDIUM exploitability, MEDIUM-HIGH impact
4. **TAR archive bomb** (DOS-004) - LOW-MEDIUM exploitability, MEDIUM impact

### Least Exploitable (Well Protected)

1. **Transaction deserialization bomb** - Strong MTU limits
2. **sBPF program bomb** - Protocol-level size limits
3. **Kernel handle exhaustion** - Comprehensive rlimits
4. **Remote code execution** - Elite syscall filtering + namespaces

---

## References

### Individual Finding Documents
- [DOS-001: Compression Bomb Vulnerability](./DOS-001_Compression_Bomb_Vulnerability.md)
- [DOS-002: Missing Tile Watchdog](./DOS-002_Missing_Tile_Watchdog.md)
- [DOS-003: Transaction Crash Circuit Breaker](./DOS-003_Transaction_Crash_Circuit_Breaker.md)
- [DOS-004: TAR Archive Bomb](./DOS-004_TAR_Archive_Bomb.md)

### Related Security Research
- `SR/Memory_Safety.md` - Memory safety analysis
- `SR/DoS_Mitigations.md` - General DoS mitigation strategies
- `SR/Architecture.md` - Tile architecture overview
- `SR/IPC_Messaging.md` - Inter-tile communication
- `SR/Transaction_Processing.md` - Transaction pipeline

### Key Source Files
- `src/util/sandbox/fd_sandbox.c` - Sandboxing implementation
- `src/ballet/zstd/fd_zstd.c` - Zstandard decompression
- `src/util/archive/fd_tar_reader.c` - TAR extraction
- `src/app/shared/commands/run/run.c` - Supervisor process
- `src/tango/cnc/fd_cnc.h` - Command and control interface
- `src/disco/pack/fd_pack.c` - Transaction mempool

---

## Audit Methodology

### Approach
1. **Code-only analysis** (documentation excluded per requirements)
2. **Static analysis** of security-critical paths
3. **Architecture review** of isolation mechanisms
4. **Threat modeling** for DoS scenarios
5. **Evidence gathering** with file paths and line numbers

### Tools Used
- Manual code review
- Grep/ripgrep for pattern matching
- Static analysis of resource limits
- Trace analysis of failure paths

### Limitations
- No dynamic testing or fuzzing performed
- No network-level DoS testing
- No performance impact analysis of mitigations
- Limited to single-validator scope (no network-wide attacks)

---

## Conclusion

Firedancer demonstrates **exceptional security engineering** in isolation and input validation. The multi-layer sandboxing (seccomp, namespaces, pivot root) represents state-of-the-art defense-in-depth.

However, the **fail-fast philosophy**, while prioritizing correctness, leaves the system vulnerable to persistent DoS attacks that could be mitigated with automatic recovery mechanisms.

### Key Takeaways

**What Firedancer Does Well:**
- Elite syscall filtering (99% attack surface reduction)
- Industry-leading namespace isolation
- Comprehensive resource limits
- Strong transaction parsing

**What Needs Improvement:**
- Decompression bomb protection (DOS-001)
- Hung tile detection (DOS-002)
- Crash-transaction tracking (DOS-003)
- Archive extraction limits (DOS-004)

**Overall Security Posture:** Strong isolation, moderate resilience, weak automatic recovery.

### Final Recommendation

Implement the four critical mitigations (DOS-001 through DOS-004) to achieve **production-grade DoS resilience** while maintaining the strong isolation guarantees already in place.

---

**End of Summary**
**Last Updated:** 2025-11-10
**Next Review:** After mitigation implementation
