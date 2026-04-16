# DOS-003: Missing Circuit Breaker for Crash-Inducing Transactions

## Severity
**MEDIUM-HIGH**

## Summary
Firedancer lacks a circuit breaker mechanism to detect and isolate transactions that repeatedly cause tile crashes. When a problematic transaction causes a bank tile to crash, there is no tracking or banning of the offending transaction, allowing it to cause repeated crashes if resubmitted or retried.

## Affected Components
- `src/discoh/bank/fd_bank_tile.c:86-331` (transaction execution - no crash tracking)
- `src/disco/pack/fd_pack.c` (transaction pool - no crash history)
- `src/disco/dedup/fd_dedup_tile.c` (deduplication - no crash-based filtering)
- `src/app/shared/commands/run/run.c:416-461` (supervisor - no crash-transaction correlation)

## Technical Details

### Vulnerability Mechanism

**Current Transaction Lifecycle:**

```
┌─────────────────────────────────────────────────────────────┐
│ Insert → Validate → Schedule → Execute → Complete → Delete  │
│                                    ↓ (crash)                 │
│                            Tile dies → Validator shuts down  │
│                                                              │
│ NO RECORD of which transaction caused the crash             │
└─────────────────────────────────────────────────────────────┘
```

**What Happens on Crash:**

From `src/app/shared/commands/run/run.c:445-457`:

```c
if( !WIFEXITED( wstatus ) ) {
  FD_LOG_ERR_NOEXIT(( "tile %s:%lu exited with signal %d (%s)",
                      tile_name, tile_id, WTERMSIG( wstatus ),
                      fd_io_strsignal( WTERMSIG( wstatus ) ) ));

  // ENTIRE VALIDATOR SHUTS DOWN
  fd_sys_util_exit_group( ... );
}
```

**The Gap:**

1. **No crash-transaction correlation**: When bank tile crashes, supervisor doesn't know which transaction caused it
2. **No transaction retry tracking**: Pack tile doesn't track if a transaction caused previous crashes
3. **No ban list**: Dedup tile doesn't filter transactions based on crash history
4. **No forensics**: Crash logs don't preserve transaction hashes for analysis

### Existing Protections (Not Sufficient)

**Skip Mechanism** (`src/disco/pack/fd_pack.c:77-84, 1846-1903`):
- Prevents infinite **scheduling** retry loops (account conflicts)
- After 50 scheduling attempts, tx skipped for rest of slot
- **Does NOT track execution crashes**

**Transaction Expiration** (`src/disco/pack/fd_pack.c:2657-2661`):
- Transactions expire after 150 slots
- **Does NOT correlate with crash events**

**Bundle Blacklist** (`src/disco/pack/fd_pack_tip_prog_blacklist.h`):
- Static program blacklist for bundles
- **Does NOT handle dynamic crash-inducing transactions**

### Attack Scenarios

**Attack Vector 1: Adversarial Transaction Replay**

1. Attacker discovers transaction that crashes bank tile:
   - Malformed sBPF program execution
   - Edge case in transaction processing
   - Memory corruption trigger
2. Validator crashes, supervisor shuts down
3. Operator restarts validator (manual or systemd)
4. **Attacker resubmits same transaction**
5. Validator crashes again
6. Repeat indefinitely → persistent DoS

**Attack Vector 2: Gossip Amplification**

1. Attacker submits crash-inducing transaction via gossip
2. Transaction propagates to multiple validators
3. All validators crash when processing it
4. Network-wide disruption if enough validators affected
5. **No mechanism prevents re-gossip after restart**

**Attack Vector 3: Mempool Persistence**

1. Crash-inducing transaction enters mempool
2. Bank tile crashes attempting execution
3. Validator restarts, mempool persists
4. **Transaction still in pack tile, retried automatically**
5. Immediate re-crash on startup

**Prerequisites:**
- Attacker can submit transactions (via RPC or gossip)
- Knowledge of crash-inducing input (fuzzing, bug discovery)
- No attribution/reputation system to ban attacker

### Impact Assessment

**Availability Impact**: HIGH
- Repeated validator crashes
- Requires manual intervention per crash
- Potential consensus impact if many validators affected
- Loss of rewards during downtime

**Recovery Time**:
- Without circuit breaker: Manual crash → restart → crash loop
- With circuit breaker: First crash → transaction banned → normal operation

**Scope**:
- Affects transaction execution tiles (bank, exec)
- Impacts pack tile scheduling
- Can affect gossip propagation

**Real-World Examples** (Hypothetical):
- Transaction with malformed sBPF program causing VM crash
- Edge case in Borsh deserialization causing segfault
- Integer overflow in compute unit calculation
- Resource exhaustion trigger (stack overflow, heap corruption)

## Proof of Concept

**Simulated Crash-Inducing Transaction:**

```c
// In fd_bank_tile.c, during_frag():

// Simulate transaction that causes crash
if( memcmp( txn->payload, "CRASHME", 7 ) == 0 ) {
  FD_LOG_ERR(( "Crash-inducing transaction detected" ));
  // Simulate various crash types:

  // Option 1: Segmentation fault
  *(volatile int*)0 = 0;

  // Option 2: Abort
  abort();

  // Option 3: Division by zero
  volatile int x = 0;
  volatile int y = 1 / x;
}
```

**Expected Behavior (with circuit breaker):**
1. Transaction causes crash
2. Supervisor logs crash + transaction hash
3. On restart, pack tile loads banned transaction list
4. Transaction hash found in ban list → dropped immediately
5. Validator operates normally

**Actual Behavior (current):**
1. Transaction causes crash
2. Validator shuts down
3. On restart, **no memory of problematic transaction**
4. If transaction resubmitted or still in gossip → crashes again
5. Infinite crash loop until transaction expires (150 slots) or manual intervention

## Exploitation Difficulty
**MEDIUM**

**Factors Increasing Difficulty:**
- Requires finding crash-inducing input (fuzzing/research)
- Firedancer has strong input validation (reduces attack surface)
- Sandbox protections limit some crash vectors

**Factors Decreasing Difficulty:**
- Once found, crash-inducing transaction is reusable
- No authentication required for transaction submission
- Gossip propagation can amplify impact
- No reputation/rate-limiting system

## Recommended Mitigations

### 1. Implement Crash-Transaction Correlation (Critical Priority)

**Add crash logging to supervisor** (`src/app/shared/commands/run/run.c`):

```c
// New structure to track recent transactions
typedef struct {
  uchar     sig[64];         // Transaction signature
  long      execution_time;  // When execution started
  uchar     valid;           // 1 if slot contains data
} fd_recent_txn_t;

#define RECENT_TXN_RING_SIZE 1024
fd_recent_txn_t recent_txns[RECENT_TXN_RING_SIZE];
ulong recent_txn_idx = 0;

// In supervisor crash handler:
if( !WIFEXITED( wstatus ) ) {
  // Find recently executed transaction
  fd_recent_txn_t * suspect = find_recent_txn_for_tile( tile_id );

  if( suspect && suspect->valid ) {
    FD_LOG_ERR(( "Tile crashed during execution of transaction %.64s",
                 fd_hex_encode( suspect->sig, 64 ) ));

    // Write to crash ban list
    append_to_ban_list( "/var/lib/firedancer/crash_ban_list.bin", suspect->sig );
  }

  fd_sys_util_exit_group( ... );
}
```

### 2. Implement Ban List in Dedup/Pack Tiles

**Load ban list on startup** (`src/disco/dedup/fd_dedup_tile.c`):

```c
// In privileged_init():
typedef struct {
  uchar sig[64];
  ulong ban_until_slot;  // Slot when ban expires (0 = permanent)
  uint  crash_count;     // How many crashes attributed to this tx
} fd_ban_entry_t;

#define MAX_BAN_LIST_SIZE 10000
fd_ban_entry_t * ban_list;

void load_ban_list( char const * path ) {
  // Load from persistent storage
  // Populate ban_list in shared memory
  // Expire old entries (ban_until_slot < current_slot)
}

// In during_frag() (transaction receive):
int is_banned( uchar const * sig ) {
  for( ulong i = 0; i < ban_list_size; i++ ) {
    if( 0 == memcmp( ban_list[i].sig, sig, 64 ) ) {
      if( ban_list[i].ban_until_slot == 0 ||
          ban_list[i].ban_until_slot > current_slot ) {
        return 1;  // Banned
      }
    }
  }
  return 0;
}

if( is_banned( txn->signature ) ) {
  FD_LOG_WARNING(( "Dropping banned transaction %.64s",
                   fd_hex_encode( txn->signature, 64 ) ));
  // Increment drop counter
  continue;  // Drop transaction
}
```

### 3. Implement Graduated Ban Durations

```c
// Ban duration based on crash frequency
ulong calculate_ban_duration( uint crash_count ) {
  switch( crash_count ) {
    case 1:  return 150UL;        // 150 slots (~1 minute)
    case 2:  return 1000UL;       // 1000 slots (~6.5 minutes)
    case 3:  return 10000UL;      // 10k slots (~1 hour)
    default: return 0UL;          // Permanent ban
  }
}
```

### 4. Add Crash Forensics Logging

**Before transaction execution** (`src/discoh/bank/fd_bank_tile.c`):

```c
// In during_frag(), before execution:
FD_LOG_INFO(( "[PRE-EXEC] txn=%.64s slot=%lu microblock=%lu",
              fd_hex_encode( txn->signature, 64 ),
              slot, microblock_idx ));

// Execute transaction
int result = fd_execute_txn( ... );

// After execution:
FD_LOG_INFO(( "[POST-EXEC] txn=%.64s result=%d",
              fd_hex_encode( txn->signature, 64 ), result ));
```

**Benefit:** On crash, last logged transaction is the culprit.

### 5. Implement Crash Metrics

```c
// Add to metrics tile
FD_MGAUGE_SET( BANK, CRASHES_TOTAL, crashes_total );
FD_MGAUGE_SET( BANK, CRASHES_LAST_TXN, last_crash_txn_sig_hex );
FD_MGAUGE_SET( BANK, BAN_LIST_SIZE, ban_list_size );
FD_MGAUGE_SET( BANK, BANNED_TXN_DROPS, banned_drops_count );
```

### 6. Protocol-Level Transaction Reputation (Long-Term)

Coordinate with Solana Labs to implement:
- Network-wide transaction ban list (via gossip)
- Reputation scoring for transaction submitters
- Rate limiting based on historical crash-causing

## Detection Strategies

### Runtime Monitoring

```bash
# Check for repeated crashes with same transaction
grep "exited with signal" /var/log/firedancer.log | \
  grep -oP "txn=[0-9a-f]{64}" | sort | uniq -c | sort -rn

# Monitor ban list size
fdctl metrics | grep ban_list_size

# Alert on repeated crashes
if [ $(grep -c "exited with signal 11" /var/log/firedancer.log) -gt 3 ]; then
  alert "Repeated crashes detected"
fi
```

### Automated Alerting

```yaml
alerts:
  - name: RepeatedCrashes
    condition: crashes_in_last_hour > 3
    action: investigate_transactions

  - name: BanListGrowing
    condition: ban_list_size > 100
    action: review_banned_transactions

  - name: HighBannedDropRate
    condition: banned_txn_drop_rate > 10/sec
    action: potential_dos_attack
```

### Post-Crash Analysis

```bash
# Extract last executed transaction from logs
tail -n 1000 /var/log/firedancer.log | \
  grep "\[PRE-EXEC\]" | tail -n 1

# Check if transaction is in ban list
fdctl ban-list check <txn_sig>

# Review crash history for transaction
fdctl ban-list history <txn_sig>
```

## Testing Recommendations

### Unit Tests

```c
// test_ban_list.c
void test_ban_list_add_remove( void ) {
  // Add transaction to ban list
  // Verify it's rejected
  // Remove from ban list
  // Verify it's accepted
}

void test_ban_expiration( void ) {
  // Add transaction with expiration
  // Advance to expiration slot
  // Verify transaction accepted after expiration
}
```

### Integration Tests

```bash
# Test 1: Transaction causes crash, gets banned
fdctl test --inject-crash-txn <txn> --expect-ban

# Test 2: Banned transaction is dropped
fdctl test --submit-banned-txn <txn> --expect-drop

# Test 3: Ban list persists across restarts
fdctl test --ban-txn <txn> --restart --verify-still-banned
```

### Fuzzing Integration

```c
// Integrate with AFL++ to automatically populate ban list
// When fuzzer finds crash:
//   1. Log crash-inducing input
//   2. Add to ban list
//   3. Continue fuzzing other paths
```

## References

### Similar Implementations
- Ethereum: "Bad block" tracking in Geth/Nethermind
- Bitcoin Core: `setban` / `listbanned` RPC commands
- PostgreSQL: Prepared statement caching with error tracking

### Security Research
- "Denial of Service via Algorithmic Complexity Attacks" (CCC 2003)
- "Circuit Breakers in Distributed Systems" (Martin Fowler)
- Netflix Hystrix: Circuit breaker pattern

### Internal References
- `SR/Transaction_Processing.md` - Transaction processing pipeline
- `src/disco/pack/fd_pack.c` - Pack tile implementation
- `src/discoh/bank/fd_bank_tile.c` - Bank tile execution

## Timeline
- **Discovered**: 2025-11-10
- **Reported**: 2025-11-10
- **Status**: UNFIXED (no crash-transaction correlation exists)

## Additional Notes

### Design Considerations

**Persistent vs. In-Memory Ban List:**
- **Persistent** (recommended): Survives restarts, prevents immediate re-crash
- **In-Memory**: Lost on restart, but simpler implementation

**Ban Duration:**
- **Temporary** (recommended): Prevents false positives from transient bugs
- **Permanent**: Risk of banning legitimate transactions due to transient conditions

**Coordination with Gossip:**
- Should banned transactions still be gossiped?
- Should ban list be shared across validators? (Risk: false positive amplification)

### False Positive Risk

**Legitimate reasons for crashes:**
- Transient memory corruption (cosmic rays)
- Hardware failures
- Non-deterministic bugs

**Mitigation:**
- Require multiple crashes (N=3) before permanent ban
- Graduated ban durations
- Manual override capability (`fdctl ban-list remove`)

### Performance Considerations

**Ban List Lookup:**
- Linear search: O(n) for n banned transactions
- Hash table: O(1) lookup, higher memory overhead
- Bloom filter: O(1) lookup, false positives acceptable (tx still validated)

**Recommendation:** Use Bloom filter for fast rejection, hash table for confirmation.

### Coordination with Existing Features

**Skip Mechanism:**
- Skip: Prevents scheduling retry loops (account conflicts)
- Ban: Prevents execution of crash-inducing transactions
- **Complementary, not redundant**

**Transaction Cache (tcache):**
- Tracks executed transactions (anti-replay)
- Ban list tracks crash-causing transactions
- **Different purposes, should coexist**

This finding is critical for production resilience as it prevents crash-induced DoS attacks that could otherwise cause repeated validator downtime.
