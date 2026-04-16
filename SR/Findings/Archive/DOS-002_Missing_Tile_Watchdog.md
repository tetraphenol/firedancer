# DOS-002: Missing Watchdog Timer for Hung Tiles

## Severity
**HIGH**

## Summary
Firedancer lacks an automatic watchdog mechanism to detect and terminate tiles that hang (infinite loops, deadlocks). While heartbeat monitoring detects stale tiles within 100ms, no automated recovery action is taken, allowing a single hung tile to stall the entire validator indefinitely.

## Affected Components
- `src/app/shared/commands/run/run.c:416-461` (supervisor process - no watchdog)
- `src/tango/cnc/fd_cnc.h:68-74` (documented ACK timeout - not implemented)
- `src/app/shared/commands/monitor/monitor.c:372` (stale detection only)
- `src/disco/stem/fd_stem.c:361-502` (heartbeat update mechanism)

## Technical Details

### Vulnerability Mechanism

Firedancer implements a **fail-fast philosophy** but lacks automatic recovery for hung (non-crashed) tiles.

**Current Implementation:**

1. **Heartbeat Monitoring** (`src/tango/cnc/fd_cnc.h:252-257`):
   ```c
   long heartbeat0;  // Initial heartbeat when CNC created
   long heartbeat;   // Current heartbeat value
   ```

   Tiles update heartbeat during housekeeping cycles (every μs to 1s).

2. **Stale Detection** (`src/app/shared/commands/monitor/monitor.c:372`):
   ```c
   printf_stale(&buf, &buf_sz,
       (long)(0.5+ns_per_tic*(double)(toc - (long)cur->heartbeat)),
       1e8 /* 100 milliseconds */);
   ```

   Monitor displays "STALE" if heartbeat hasn't updated in 100ms.

3. **Supervisor Behavior** (`src/app/shared/commands/run/run.c:416-461`):
   ```c
   while( 1 ) {
     poll( fds, 1UL+child_cnt, -1 );

     int wstatus;
     int exited_pid = wait4( -1, &wstatus, (int)__WALL | (int)WNOHANG, NULL );

     if( !WIFEXITED( wstatus ) ) {
       FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d (%s)",
                           tile_name, tile_id, WTERMSIG( wstatus ),
                           fd_io_strsignal( WTERMSIG( wstatus ) ) ));
       fd_sys_util_exit_group( ... );  // KILL ALL TILES
     }
   }
   ```

**The Gap:**
- **Tile crashes** → Supervisor logs error → Entire validator shuts down ✓
- **Tile hangs (alive but frozen)** → Monitor shows "STALE" → **No automatic action** ✗

### Documented But Not Implemented

From `src/tango/cnc/fd_cnc.h:68-74`:

```c
/* A cnc thread can signal ACK to the app thread. If the cnc returns to
   RUN reasonably promptly, the app thread has self-reported to the cnc
   thread it is operating correctly. If it doesn't (i.e. times out), the
   cnc thread can forcibly terminate the app thread... */
```

**This timeout/force-termination mechanism is NOT implemented in production code.**

Only found in test code (`src/tango/cnc/test_cnc.c:170`):
```c
// Wait up to 30 seconds for ACK (test only, not in production)
ulong timeout = 30UL * 1000000000UL;
```

### Attack Scenarios

**Attack Vector 1: Infinite Loop via Malicious Transaction**
1. Attacker crafts transaction that triggers infinite loop in bank tile
2. Bank tile stops updating heartbeat
3. Monitor shows "STALE" after 100ms
4. **Validator stalls indefinitely** - no automatic recovery
5. Requires manual intervention to restart

**Attack Vector 2: Deadlock Between Tiles**
1. Trigger circular dependency between tiles via IPC
2. Both tiles block waiting for each other
3. Heartbeats stop updating
4. Monitor shows both "STALE"
5. **Entire validator frozen** - no automatic recovery

**Attack Vector 3: Resource Exhaustion Loop**
1. Trigger memory pressure in specific tile
2. Tile enters tight loop attempting allocation
3. Heartbeat updates stop (too busy to housekeep)
4. Monitor detects stale but takes no action
5. Downstream tiles backpressure and stall

### Impact Assessment

**Availability Impact**: CRITICAL
- Single hung tile can stall entire validator
- No automatic recovery mechanism
- Requires human intervention to restart
- Potential loss of validator rewards during downtime

**Scope**:
- Affects all tile types
- Any code path that can enter infinite loop
- Any scenario causing deadlock
- Spin loops during resource contention

**Real-World Scenarios**:
- Bug in transaction execution logic
- Unexpected input causing parser loop
- Memory allocator deadlock
- IPC protocol violation

## Proof of Concept

**Simulated Tile Hang:**

```c
// In any tile's run() function, add:
void run( fd_topo_t * topo, fd_topo_tile_t * tile ) {
  for(;;) {
    // Intentionally hang without updating heartbeat
    for( volatile ulong i = 0; i < ULONG_MAX; i++ ) {
      // Busy loop - heartbeat never updates
    }
  }
}
```

**Expected Behavior (with watchdog):**
1. Tile hangs
2. Watchdog detects no heartbeat after 5 seconds
3. Watchdog sends SIGKILL to hung tile
4. Tile restarts or validator shuts down gracefully

**Actual Behavior (current):**
1. Tile hangs
2. Monitor shows "STALE" after 100ms
3. **Nothing happens automatically**
4. Validator stalled until manual restart

## Exploitation Difficulty
**MEDIUM-HIGH**

**Factors Increasing Difficulty:**
- Requires finding code path that can hang tile
- May require specific transaction or input crafting
- Firedancer code is generally defensive against hangs

**Factors Decreasing Difficulty:**
- No automatic recovery means any successful hang is permanent
- Multiple potential attack surfaces (txn parsing, execution, IPC)
- Standard debugging techniques can find hang-vulnerable code

## Recommended Mitigations

### 1. Implement Tile Watchdog (Critical Priority)

Add to `src/app/shared/commands/run/run.c`:

```c
#define WATCHDOG_TIMEOUT_NS (5UL * 1000000000UL)  // 5 seconds

// In supervisor loop:
while( 1 ) {
  poll( fds, 1UL+child_cnt, 100 /* 100ms poll timeout */ );

  long now = fd_log_wallclock();

  // Check each tile's heartbeat
  for( ulong i = 0; i < child_cnt; i++ ) {
    fd_cnc_t * cnc = child[i].cnc;
    long heartbeat = fd_cnc_heartbeat_query( cnc );
    long age_ns = now - heartbeat;

    if( age_ns > WATCHDOG_TIMEOUT_NS ) {
      FD_LOG_ERR(( "Tile %s:%lu hung (heartbeat age: %.2fs), terminating",
                   child[i].name, child[i].id, age_ns / 1e9 ));

      // Send SIGKILL to hung tile
      kill( child[i].pid, SIGKILL );

      // Decision point: restart tile OR shutdown validator
      fd_sys_util_exit_group( 1 );  // For now, fail-fast
    }
  }

  // ... existing wait4() logic ...
}
```

### 2. Implement CNC ACK Timeout Mechanism

Complete the documented ACK timeout feature in `src/tango/cnc/fd_cnc.c`:

```c
int
fd_cnc_wait_ack( fd_cnc_t * cnc, ulong timeout_ns ) {
  long start = fd_log_wallclock();
  ulong signal;

  do {
    signal = fd_cnc_signal_query( cnc );
    if( signal == FD_CNC_SIGNAL_RUN ) return 0;  // ACK received

    long now = fd_log_wallclock();
    if( (ulong)(now - start) > timeout_ns ) {
      FD_LOG_WARNING(( "CNC ACK timeout after %lu ns", timeout_ns ));
      return -1;  // Timeout
    }

    FD_SPIN_PAUSE();
  } while( 1 );
}
```

### 3. Add Per-Tile Configurable Timeouts

Different tiles may have different legitimate maximum processing times:

```c
// In fd_topo_run_tile_t structure:
struct fd_topo_run_tile_t {
  // ... existing fields ...
  ulong watchdog_timeout_ns;  // Per-tile timeout (0 = use default)
};

// Examples:
verify_tile.watchdog_timeout_ns   = 1 * 1000000000UL;   // 1 second
bank_tile.watchdog_timeout_ns     = 10 * 1000000000UL;  // 10 seconds (block execution)
quic_tile.watchdog_timeout_ns     = 5 * 1000000000UL;   // 5 seconds
```

### 4. Graceful Degradation Strategy

Instead of immediate shutdown, implement staged response:

```
Stage 1 (5s):  Log warning, continue monitoring
Stage 2 (10s): Attempt graceful tile restart (send SIGTERM)
Stage 3 (15s): Force kill tile (send SIGKILL)
Stage 4 (20s): Shutdown validator (fail-fast)
```

### 5. Add Deadlock Detection

Implement cycle detection in IPC graph:

```c
// Track tile dependencies via CNC signals
// Use depth-first search to detect circular waits
int fd_topo_detect_deadlock( fd_topo_t * topo ) {
  // For each tile, check if waiting on another tile
  // Build dependency graph
  // Run cycle detection algorithm
  // Return 1 if deadlock detected
}
```

## Detection Strategies

### Runtime Monitoring

Monitor metrics for potential hangs:

```bash
# Alert if any tile heartbeat age > 1 second
fdctl monitor | grep -i stale

# Track heartbeat age over time
fdctl metrics | grep heartbeat_age_ms
```

### Automated Alerting

```yaml
alerts:
  - name: TileHeartbeatStale
    condition: heartbeat_age_ms > 1000
    action: page_oncall

  - name: TileHung
    condition: heartbeat_age_ms > 5000
    action: restart_validator

  - name: MultiTileStale
    condition: count(stale_tiles) > 1
    action: investigate_deadlock
```

### Logging Enhancements

Add to heartbeat monitoring:

```c
// Log when tile goes stale
if( age_ms > 100 && !tile->previously_stale ) {
  FD_LOG_WARNING(( "Tile %s:%lu heartbeat stale (age: %lu ms)",
                   tile->name, tile->id, age_ms ));
  tile->previously_stale = 1;
}

// Log when tile recovers
if( age_ms <= 100 && tile->previously_stale ) {
  FD_LOG_INFO(( "Tile %s:%lu heartbeat recovered", tile->name, tile->id ));
  tile->previously_stale = 0;
}
```

## Testing Recommendations

### Unit Tests

```c
// test_tile_watchdog.c
void test_hung_tile_detection( void ) {
  // Launch tile
  // Stop heartbeat updates
  // Verify watchdog detects hang within timeout
  // Verify watchdog terminates tile
}

void test_false_positive_prevention( void ) {
  // Launch tile with slow but legitimate operation
  // Verify watchdog does NOT trigger
}
```

### Integration Tests

```bash
# Test 1: Verify watchdog kills hung verify tile
fdctl test --hang-tile verify --expect-watchdog-kill

# Test 2: Verify watchdog does not kill slow but healthy tile
fdctl test --slow-tile bank --expect-no-watchdog

# Test 3: Verify deadlock detection
fdctl test --create-deadlock --expect-detection
```

## References

### Industry Standards
- POSIX watchdog timers
- systemd watchdog support (`WatchdogSec=`)
- Kubernetes liveness probes

### Similar Implementations
- PostgreSQL: `wal_sender_timeout`, `wal_receiver_timeout`
- Nginx: `fastcgi_read_timeout`, `proxy_read_timeout`
- Linux kernel: `softlockup_panic`, `hung_task_timeout_secs`

### Internal References
- `SR/Architecture.md` - Tile architecture
- `SR/IPC_Messaging.md` - Inter-tile communication
- `src/tango/cnc/fd_cnc.h` - Command and control interface

## Timeline
- **Discovered**: 2025-11-10
- **Reported**: 2025-11-10
- **Status**: UNFIXED (documented in comments but not implemented)

## Additional Notes

The Firedancer team has documented the intended ACK timeout mechanism in `fd_cnc.h` comments, showing awareness of this need. However, the production implementation follows a strict fail-fast model where:

1. Crashed tiles trigger immediate validator shutdown
2. Hung tiles are only passively monitored (no recovery)

This is a valid design choice prioritizing **correctness over availability**, assuming:
- External orchestration (systemd, Kubernetes) handles validator restarts
- Human operators monitor for hangs
- Code quality prevents hangs through defensive programming

However, for production resilience, an automatic watchdog would provide:
- Faster detection and recovery
- Reduced operator burden
- Better handling of transient hangs
- Improved validator uptime metrics

The implementation should be configurable to allow operators to choose between:
- **Fail-fast mode** (current): Any hang → shutdown
- **Auto-recovery mode** (proposed): Hung tile → kill → restart → shutdown if persistent
