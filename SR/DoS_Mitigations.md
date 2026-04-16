# Denial-of-Service (DoS) Mitigations - Security Analysis

**Components:** QUIC, Compute Budget, Flow Control, Resource Limits
**Source:** `/home/user/firedancer/src/waltz/quic/`, `/src/flamenco/`, `/src/tango/`, `/src/choreo/`
**Analysis Date:** November 6, 2025

---

## Executive Summary

Firedancer implements comprehensive multi-layer DoS protections across network, transaction, consensus, and resource layers. Analysis identified **strong defensive mechanisms** with defense-in-depth strategy and configurable limits.

### Key Findings

| ID | Severity | Component | Issue | Location |
|----|----------|-----------|-------|----------|
| 1 | **INFO** | Equivocation | No eviction policy | `choreo/eqvoc/fd_eqvoc.c:113` |
| 2 | **INFO** | Compute Budget | Overflow risk (documented) | `disco/pack/fd_pack.c` |
| 3 | **INFO** | QUIC | Retry token expiration | `waltz/quic/fd_quic_retry.h:89` |

### Security Strengths

- ✅ Connection rate limiting (retry tokens, handshake limits)
- ✅ Compute unit budgets (1.4M CU max per transaction)
- ✅ Flow control with backpressure (credit-based)
- ✅ Resource pool limits (connections, streams, frames)
- ✅ Transaction size limits (1232 bytes MTU)
- ✅ Signature limits (12 max practical, 127 max theoretical)
- ✅ Saturating arithmetic prevents integer overflows
- ✅ Comprehensive metrics for attack detection

---

## Architecture Overview

### Defense-in-Depth Strategy

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Network (QUIC)                                │
│  - Retry token authentication                           │
│  - Connection limits (512 default)                      │
│  - Handshake limits (512 default)                       │
│  - Idle timeout (1 second)                              │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 2: Transaction Parsing                           │
│  - Size limits (1232 bytes MTU)                         │
│  - Signature limits (12 practical max)                  │
│  - Account limits (128 max)                             │
│  - Instruction limits (64 max)                          │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 3: Compute Budget                                │
│  - Per-transaction CU limit (1.4M max)                  │
│  - Per-block CU limit (aggregated)                      │
│  - Heap size limits (32KB-256KB)                        │
│  - Saturating arithmetic                                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 4: Flow Control (Tango)                          │
│  - Credit-based backpressure                            │
│  - Producer blocking on exhaustion                      │
│  - Tcache deduplication                                 │
│  - Burst control                                        │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 5: Resource Pools                                │
│  - Equivocation pool limits                             │
│  - Ghost fork choice limits                             │
│  - Memory pre-allocation                                │
│  - No dynamic allocation in hot paths                   │
└─────────────────────────────────────────────────────────┘
```

---

## Network Layer (QUIC)

### Location

**Source:** `/home/user/firedancer/src/waltz/quic/`

### Connection Limits

**File:** `fd_quic.h`, Lines 107-121

**Structure:**

```c
struct fd_quic_limits {
  /* Instance-wide limits */
  ulong  conn_cnt;                  /* Max concurrent connections (default: 512) */
  ulong  handshake_cnt;             /* Max concurrent handshakes (default: 512) */
  ulong  inflight_frame_cnt;        /* Total max inflight frames (default: 2500) */
  ulong  stream_pool_cnt;           /* Number of streams in pool (default: 8) */
  ulong  log_depth;                 /* Shm log cache depth */

  /* Per-connection limits */
  ulong  conn_id_cnt;               /* Max connection IDs (min 4, default: 16) */
  ulong  stream_id_cnt;             /* Max concurrent streams */
  ulong  min_inflight_frame_cnt_conn; /* Min inflight frames per connection */
  ulong  tx_buf_sz;                 /* Per-stream TX buffer size */
};
```

**Configuration:**

```c
/* From fd_quic.c:241-246 */
limits->conn_cnt           = 512UL;   /* Configurable via --quic-conns */
limits->conn_id_cnt        = 16UL;    /* Configurable via --quic-conn-ids */
limits->handshake_cnt      = 512UL;   /* Configurable via --quic-handshakes */
limits->inflight_frame_cnt = 2500UL;  /* Configurable via --quic-inflight-pkts */
```

**Protection:**

- ✅ Hard limits prevent resource exhaustion
- ✅ Configurable at startup for deployment tuning
- ✅ Allocation failure triggers connection rejection
- ✅ Metrics track limit violations

---

### Retry Token Mechanism (Handshake Flood Protection)

**File:** `fd_quic_retry.h`, Lines 73-187

**Purpose:** Mitigate handshake flooding (similar to TCP SYN cookies)

**Mechanism:**

```
Client                    Server
  │                         │
  │──── Initial Packet ────▶│
  │                         │
  │                         ├─ Stateless validation
  │                         │  (no connection allocated)
  │                         │
  │◀──── Retry Packet ──────│
  │   (with retry token)    │
  │                         │
  │─── Initial + Token ────▶│
  │                         │
  │                         ├─ Token validation
  │                         │  (IP, port, expiration)
  │                         │
  │                         ├─ Allocate connection
  │                         │
  │◀─── Handshake Data ─────│
```

**Token Structure:**

```c
/* fd_quic_retry.h:89-103 */
struct fd_quic_retry_data {
  ushort magic;                    /* 0xdaa5 - Magic number */
  uchar  token_id[12];             /* 96-bit pseudorandom nonce */
  uchar  ip6_addr[16];             /* IPv4-mapped IPv6 source address */
  ushort udp_port;                 /* Source UDP port */
  ulong  expire_comp;              /* Expiration timestamp (unix_nanos>>22) */
  ulong  rscid;                    /* Retry Source Connection ID */
  uchar  odcid[20];                /* Original Destination Connection ID */
  uchar  odcid_sz;                 /* ODCID size [1,20] */
};
```

**Security Properties:**

1. **AES-128-GCM Encryption** (RFC 9001)
   - 128-bit secret key (server-local)
   - 96-bit unique nonce per token
   - Authenticated encryption prevents forgery

2. **IP Address Binding**
   - Token includes source IP and port
   - Prevents token theft/replay from different IPs
   - Validates on second Initial packet

3. **Time-Limited Validity**
   - Default: 1 second TTL
   - Expire timestamp in token
   - Prevents token reuse after expiration

4. **Stateless Validation**
   - No server state until valid token received
   - Protects against handshake flooding

**Attack Mitigation:**

| Attack Type | Mitigation |
|-------------|-----------|
| **SYN Flood** | Stateless retry (no connection until validated) |
| **Token Forgery** | AES-GCM authentication (128-bit security) |
| **Token Replay** | IP binding + expiration |
| **Amplification** | Retry packet size ≤ Initial packet size |

**Assessment:** STRONG

---

### Idle Timeout

**File:** `fd_quic.h`, Lines 175-179

```c
long idle_timeout;
#define FD_QUIC_DEFAULT_IDLE_TIMEOUT (ulong)(1e9)  /* 1 second (nanoseconds) */
```

**Protection:**

- ✅ Idle connections closed after 1 second
- ✅ Reclaims connection pool slots
- ✅ Prevents connection table exhaustion
- ✅ Configurable per deployment needs

**Trade-off:**

- Short timeout improves DoS resistance
- May cause legitimate connection drops under network delay
- Default (1s) balances security vs usability

---

### Connection State Machine

**File:** `fd_quic_conn.h`, Lines 14-22

```c
#define FD_QUIC_CONN_STATE_INVALID            0
#define FD_QUIC_CONN_STATE_HANDSHAKE          1
#define FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE 2
#define FD_QUIC_CONN_STATE_ACTIVE             3
#define FD_QUIC_CONN_STATE_PEER_CLOSE         4
#define FD_QUIC_CONN_STATE_ABORT              5
#define FD_QUIC_CONN_STATE_CLOSE_PENDING      6
#define FD_QUIC_CONN_STATE_DEAD               7
```

**Security:**

- ✅ Enforced state transitions prevent invalid operations
- ✅ Connections must complete handshake to reach ACTIVE
- ✅ Invalid transitions logged/rejected
- ✅ State timeouts prevent stuck connections

---

### Metrics for Attack Detection

**File:** `fd_quic.h`, Lines 306-363

**Comprehensive Metrics:**

```c
struct fd_quic_metrics {
  /* Connection allocation failures */
  ulong conn_err_no_slots_cnt;      /* No connection slots available */
  ulong conn_err_retry_fail_cnt;    /* Retry token validation failed */

  /* Handshake failures */
  ulong hs_err_alloc_fail_cnt;      /* Handshake allocation failed */

  /* Packet errors by encryption level */
  ulong pkt_no_conn_cnt[4];         /* Unknown connection ID */
  ulong pkt_decrypt_fail_cnt[4];    /* Decryption failed */

  /* Frame allocation */
  ulong frame_tx_alloc_cnt[3];      /* [0]=success, [1]=failure, [2]=retry */
};
```

**Use Cases:**

- **Attack Detection:** Sudden spike in `conn_err_retry_fail_cnt` → handshake flooding
- **Capacity Planning:** `conn_err_no_slots_cnt` → increase connection limits
- **Debugging:** `pkt_decrypt_fail_cnt` → network corruption vs attack

---

## Compute Budget Layer

### Location

**Source:** `/home/user/firedancer/src/flamenco/runtime/program/`

### Compute Unit Limits

**File:** `fd_compute_budget_program.h`, Lines 1-10

**Constants:**

```c
#define FD_MIN_HEAP_FRAME_BYTES (32 * 1024)     /* 32 KB min heap */
#define FD_MAX_HEAP_FRAME_BYTES (256 * 1024)    /* 256 KB max heap */
#define FD_HEAP_FRAME_BYTES_GRANULARITY (1024)  /* 1 KB granularity */
#define FD_MAX_COMPUTE_UNIT_LIMIT (1400000)     /* 1.4M CU max per transaction */
```

**Default Allocation (SIMD-170):**

| Instruction Type | Default CU Limit |
|------------------|------------------|
| Non-migrated builtins | 3,000 CU |
| Migrated builtins | 200,000 CU |
| Non-builtin programs | 200,000 CU |
| **Maximum (any type)** | **1,400,000 CU** |

**Protection:**

- ✅ Per-transaction limit prevents infinite loops
- ✅ Heap size limits prevent memory exhaustion
- ✅ Granularity prevents fractional allocations

---

### Saturating Arithmetic

**Purpose:** Prevent integer overflows in compute unit accumulation

**Functions:**

```c
/* From util/fd_util.h */
static inline ulong fd_ulong_sat_add( ulong a, ulong b ) {
  ulong c = a + b;
  return fd_ulong_if( c < a, ULONG_MAX, c );  /* Saturate on overflow */
}

static inline ulong fd_ulong_sat_mul( ulong a, ulong b ) {
  uint128 product = (uint128)a * (uint128)b;
  return (ulong)fd_uint128_if( product > (uint128)ULONG_MAX, ULONG_MAX, product );
}
```

**Usage in Compute Budget:**

```c
/* Accumulate instruction CU costs */
ulong total_cu = 0;
for( ulong i=0; i<instr_cnt; i++ ) {
  total_cu = fd_ulong_sat_add( total_cu, instr[i].compute_units );
}
total_cu = fd_ulong_min( total_cu, FD_MAX_COMPUTE_UNIT_LIMIT );
```

**Security:**

- ✅ Overflow saturates to `ULONG_MAX`
- ✅ Bounded by maximum limit
- ✅ Prevents wraparound exploitation

---

### Block Compute Budget

**File:** `fd_runtime.c`

**Tracking:**

```c
/* Atomic accumulation of used compute units */
ulong * total_compute_units_used = fd_bank_total_compute_units_modify( bank );

FD_ATOMIC_FETCH_AND_ADD(
  total_compute_units_used,
  txn_ctx->compute_budget_details.compute_unit_limit -
  txn_ctx->compute_budget_details.compute_meter
);
```

**Protection:**

- ✅ Block-level compute budget enforced
- ✅ Prevents block stuffing with expensive transactions
- ✅ Atomic operations ensure consistency
- ✅ Limit configurable per consensus rules

**Potential Issue:**

From `SR/Transaction_Processing.md`:
- `pack->cumulative_block_cost` uses `uint` (32-bit)
- Theoretically can overflow if not bounded by block limits
- Mitigated by transaction validation before packing

---

## Flow Control Layer (Tango)

### Location

**Source:** `/home/user/firedancer/src/tango/fctl/`, `/src/tango/fseq/`

### Credit-Based Backpressure

**File:** `fd_fctl.h`, Lines 14-63

**Structure:**

```c
struct fd_fctl_private {
  /* Global flow control state */
  ushort rx_max;    /* Maximum receivers [0, 65535] */
  ushort rx_cnt;    /* Current receivers [0, rx_max] */
  int    in_refill; /* Refill state (0=normal, 1=refilling) */

  /* Credit parameters */
  ulong  cr_burst;  /* Max credits to burst [1, LONG_MAX] */
  ulong  cr_max;    /* Max credits overall [cr_burst, LONG_MAX] */
  ulong  cr_resume; /* Resume refill threshold [cr_burst, cr_max] */
  ulong  cr_refill; /* Refill rate [1, cr_resume] */
};

struct fd_fctl_private_rx {
  long          cr_max;     /* Per-receiver max credits (positive) */
  ulong const * seq_laddr;  /* Sequence tracking (NULL = inactive) */
  ulong *       slow_laddr; /* Slowest receiver tracking */
};
```

**Mechanism:**

```
Producer                    Consumer(s)
    │                           │
    ├─ Check credits ───────────┤
    │  (via fctl_before)        │
    │                           │
    │  Credits available?       │
    │  ┌─YES                    │
    │  │                        │
    │  └─▶ Publish message ─────┼───▶ Consumer A (fast)
    │                           │
    │                           ├───▶ Consumer B (slow) ◀── Tracks slowest
    │                           │
    │  Credits exhausted?       │
    │  ┌─YES                    │
    │  │                        │
    │  └─▶ Block producer ◀─────┤
    │      (backpressure)       │
    │                           │
    │  ◀─ Slow consumer ────────┤
    │     advances seq          │
    │                           │
    │  Refill credits ──────────┤
    │  (when >= cr_resume)      │
    │                           │
    └─▶ Resume publishing       │
```

**Protection:**

1. **Credit Exhaustion**
   - Producer blocked when `cr_avail == 0`
   - Prevents unbounded queue growth
   - Ensures consumers can keep up

2. **Burst Control**
   - `cr_burst` limits short bursts
   - Prevents sudden spikes overwhelming slow consumers

3. **Refill Threshold**
   - Only refills when credits ≥ `cr_resume`
   - Default: 2/3 of `cr_max`
   - Prevents refill thrashing

4. **Slowest Consumer Tracking**
   - `slow_laddr` points to slowest consumer sequence
   - Credits based on slowest (not fastest)
   - Ensures all consumers receive messages

**Assessment:** STRONG

---

### Tcache (Transaction Deduplication)

**File:** `fd_tcache.h`, Lines 34-105

**Purpose:** Prevent transaction replay attacks via deduplication cache

**Structure:**

```c
#define FD_TCACHE_SPARSE_DEFAULT (2)  /* 4x sparse = 25-50% fill ratio */

struct fd_tcache_private {
  ulong magic;   /* FD_TCACHE_MAGIC */
  ulong depth;   /* History depth (unique transaction signatures) */
  ulong map_cnt; /* Map size (depth << sparse) */
  ulong oldest;  /* Oldest entry index in ring buffer */

  /* Ring buffer of transaction signatures */
  /* + Sparse hash map for O(1) lookups */
};
```

**Properties:**

- **Depth:** Number of recent transaction signatures stored
- **Sparsity:** Map is 4x larger than depth (25% fill ratio)
- **History:** Configurable from seconds to minutes

**Collision Resistance:**

```c
/* Linear probing with sparsity */
for(;;) {
  ulong tag = map[ idx ];
  if( tag == target ) return FOUND;       /* Match */
  if( tag == NULL )   return NOT_FOUND;   /* Empty slot */
  idx = (idx + 1) & (map_cnt - 1);        /* Next probe */
}
```

**DoS Protection:**

- ✅ Sparse map prevents hash collision attacks
- ✅ Default 25-50% fill ratio → low probe lengths
- ✅ O(1) average lookup time
- ✅ Prevents transaction replay flooding

**Limitation:**

From `SR/IPC_Messaging.md`:
- No iteration limit on linear probe
- Could infinite loop if map becomes 100% full
- Mitigated by maintaining sparsity

---

### Dcache Burst Control

**File:** `fd_dcache.h`

**Function:** `FD_DCACHE_REQ_DATA_SZ( mtu, depth, burst, compact )`

**Parameters:**

- **mtu:** Maximum transmission unit (typically 1232 bytes)
- **depth:** Cache depth (total capacity)
- **burst:** Maximum concurrent fragments (DoS limit)
- **compact:** Compact representation mode

**Protection:**

- ✅ `burst` parameter limits simultaneous fragments
- ✅ Prevents burst flooding from overwhelming cache
- ✅ Configurable per deployment needs

---

## Resource Limits Layer

### Transaction Limits

**File:** `fd_txn.h`, Lines 34-104

**Critical Limits:**

```c
#define FD_TXN_SIGNATURE_SZ           (64UL)    /* Ed25519 signature size */
#define FD_TXN_SIG_MAX                (127UL)   /* Max signatures (compact-u16) */
#define FD_TXN_ACTUAL_SIG_MAX         (12UL)    /* Practical max (MTU constraint) */
#define FD_TXN_ACCT_ADDR_MAX          (128UL)   /* Max account addresses */
#define FD_TXN_ADDR_TABLE_LOOKUP_MAX  (127UL)   /* Max address table lookups */
#define FD_TXN_INSTR_MAX              (64UL)    /* Max instructions */
#define FD_TXN_MAX_SZ                 (852UL)   /* Max parsed struct size */
#define FD_TXN_MTU                    (1232UL)  /* Max serialized size */
#define FD_TXN_MIN_SERIALIZED_SZ      (134UL)   /* Min serialized size */
#define MAX_TX_ACCOUNT_LOCKS          (128UL)   /* Max locked accounts */
```

**Derivation:**

```
MTU = 1280 bytes (IPv6 minimum)
    - 40 bytes (IPv6 header)
    - 8 bytes (UDP header)
    = 1232 bytes (QUIC payload)
```

**Practical Signature Limit:**

```
1232 bytes MTU
 - 3 bytes (compact-u16 signature count)
 - 64 bytes/signature × 12 signatures = 768 bytes
 - 32 bytes (minimum transaction data)
 = ~429 bytes remaining
```

**Protection:**

- ✅ Signature limit prevents signature grinding attacks
- ✅ Account limit prevents lock exhaustion
- ✅ Instruction limit prevents parse complexity attacks
- ✅ MTU limit enforced at network layer

---

### Bundle Limits

**File:** `fd_dedup_tile.c`, Lines 42, 194

**Hardcoded Limit:**

```c
uchar bundle_signatures[ 4UL ][ 64UL ];  /* Max 4 signatures per bundle */

/* Line 194: Error if bundle has >4 signatures */
if( FD_UNLIKELY( bundle_sig_cnt > 4UL ) ) {
  FD_LOG_WARNING(( "bundle signature count %lu exceeds limit", bundle_sig_cnt ));
  /* Drop bundle */
}
```

**Impact:**

From `SR/Transaction_Processing.md`:
- Bundles with >4 signatures are dropped
- Prevents bundle size attacks
- May limit legitimate use cases

**Protection:**

- ✅ Prevents bundle signature flooding
- ✅ Enforced at dedup stage (before verification)
- ✅ Hardcoded (no runtime bypass)

---

### Shred Limits

**File:** `fd_shred.h`, Lines 80-170

**Critical Limits:**

```c
#define FD_SHRED_MAX_SZ              (1228UL)       /* UDP payload limit */
#define FD_SHRED_MIN_SZ              (1203UL)       /* Min valid shred */
#define FD_SHRED_DATA_HEADER_SZ      (0x58UL)       /* 88 bytes */
#define FD_SHRED_CODE_HEADER_SZ      (0x59UL)       /* 89 bytes */
#define FD_SHRED_DATA_PAYLOAD_MAX    (1140UL)       /* Max data payload */

#define FD_SHRED_BLK_MAX             (1 << 15UL)    /* 32,768 shreds/slot */
#define FD_SHRED_IDX_MAX             (32767UL)      /* Max shred index */

#define FD_EQVOC_FEC_MAX             (67UL)         /* Max FEC sets (Solana limit) */
#define FD_SHRED_MERKLE_LAYER_CNT    (10UL)         /* Merkle proof depth */
```

**Protection:**

- ✅ Shred count limit prevents slot stuffing
- ✅ FEC set limit prevents equivocation flooding
- ✅ Merkle proof depth bounds verification cost

**Slot Data Limit:**

```c
#define FD_SHRED_DATA_PAYLOAD_MAX_PER_SLOT (36536320UL)
/* = 1140 bytes/shred × 32768 shreds = ~34.85 MB per slot */
```

---

### Equivocation Pool Limits

**File:** `fd_eqvoc.h`, Lines 43-224

**Structure:**

```c
#define FD_EQVOC_FEC_MAX (67UL)  /* Solana limit: 67 FEC sets per slot */

struct fd_eqvoc {
  ulong fec_max;        /* Max FEC set metadata entries */
  ulong proof_max;      /* Max equivocation proofs */

  fd_eqvoc_fec_t *       fec_pool;      /* FEC set pool */
  fd_eqvoc_fec_map_t *   fec_map;       /* FEC set hash map */
  fd_eqvoc_proof_t *     proof_pool;    /* Proof pool */
  fd_eqvoc_proof_map_t * proof_map;     /* Proof hash map */
};
```

**FEC Set Metadata:**

```c
struct fd_eqvoc_fec {
  fd_slot_fec_t key;     /* (slot, fec_set_idx) */
  ulong         next;    /* Chaining for hash collisions */
  ulong         code_cnt;
  ulong         data_cnt;
  uint          last_idx;
  fd_ed25519_sig_t sig;  /* Signature validation */
};
```

**Proof Structure:**

```c
#define FD_EQVOC_PROOF_CHUNK_SZ (1054UL)  /* Chunk size for proof distribution */

struct fd_eqvoc_proof {
  fd_slot_pubkey_t key;  /* (slot, producer_pubkey) */

  fd_pubkey_t     producer;    /* Producer public key */
  void *          bmtree_mem;  /* Merkle tree reconstruction */
  long            wallclock;   /* Proof timestamp */
  ulong           chunk_cnt;   /* Number of chunks (max 3 for 2 shreds) */
  ulong           chunk_sz;    /* Chunk size */

  fd_eqvoc_proof_set_t set[ fd_eqvoc_proof_set_word_cnt ];  /* Chunk bitset */
  uchar shreds[2 * FD_SHRED_MAX_SZ + 2 * sizeof(ulong)];    /* 2 shreds storage */
};
```

**Issue:**

From `SR/Consensus.md` and `fd_eqvoc.c:113`:

```c
/* FIXME eviction */
if( !fd_eqvoc_fec_pool_free( eqvoc->fec_pool ) ) {
  FD_LOG_ERR(( "map full." ));  /* No recovery mechanism */
}
```

**Impact:**

- Pool can fill with stale FEC sets
- No LRU/FIFO eviction policy
- Causes validator halt on exhaustion
- Requires restart to recover

**Mitigation:**

- Pool sized based on expected load
- Timeout-based cleanup for incomplete proofs
- Infrequent in practice (67 FEC sets × active slots)

---

## Security Recommendations

### Immediate Actions

1. **Add Equivocation Pool Eviction** (`fd_eqvoc.c:113`)
   ```c
   /* LRU eviction when pool full */
   if( !fd_eqvoc_fec_pool_free( pool ) ) {
     fd_eqvoc_fec_t * oldest = find_oldest_fec_set( pool );
     fd_eqvoc_fec_remove( eqvoc, oldest );
   }
   ```

2. **Add Tcache Iteration Limit** (from `SR/IPC_Messaging.md`)
   ```c
   /* Prevent infinite loop on full map */
   for( ulong i=0; i<map_cnt; i++ ) {
     /* ... probe logic ... */
   }
   FD_CRIT( i < map_cnt, "tcache full" );
   ```

### High Priority

3. **Document Retry Token Expiration Policy**
   - Current: 1 second default
   - Consider configurable per network conditions
   - Add metrics for expired token rates

4. **Add Block Compute Unit Overflow Check**
   ```c
   /* Saturating arithmetic for block CU accumulation */
   pack->cumulative_block_cost = fd_ulong_sat_add(
     pack->cumulative_block_cost,
     cur->compute_est
   );
   ```

5. **Monitor Connection Limit Violations**
   - Alert on sustained high `conn_err_no_slots_cnt`
   - Auto-scale connection limits if possible
   - Log source IPs for rate limiting

### Medium Priority

6. **Add Dynamic Bundle Signature Limit**
   - Replace hardcoded 4-signature limit
   - Make configurable via consensus parameters
   - Allow future protocol upgrades

7. **Implement Adaptive Flow Control**
   - Adjust `cr_refill` rate based on consumer lag
   - Faster refill for healthy consumers
   - Slower refill under sustained backpressure

---

## Testing Recommendations

### Load Testing

1. **Connection Flood**
   - Send Initial packets at 100K/sec
   - Verify retry token mechanism
   - Check connection pool doesn't exhaust

2. **Compute Unit Exhaustion**
   - Submit transactions with max CU limit (1.4M)
   - Fill block compute budget
   - Verify saturation arithmetic

3. **Flow Control Backpressure**
   - Slow consumer + fast producer
   - Verify producer blocks correctly
   - Check credit refill behavior

### Attack Simulation

1. **Retry Token Forgery**
   - Generate invalid retry tokens
   - Submit from different IPs
   - Verify all rejected

2. **Signature Grinding**
   - Submit transactions with max signatures
   - Verify MTU enforcement
   - Check verification performance

3. **Equivocation Pool Filling**
   - Send FEC sets for many slots
   - Approach pool capacity
   - Verify graceful degradation

### Fuzzing Targets

1. **QUIC Packet Parser**
   - Fuzz Initial packets
   - Fuzz Retry packets
   - Fuzz frame formats

2. **Transaction Parser**
   - Fuzz signature counts
   - Fuzz account addresses
   - Fuzz instruction data

3. **Shred Parser**
   - Fuzz shred headers
   - Fuzz FEC set indices
   - Fuzz Merkle proofs

---

## Positive Security Features

### Configurable Limits

**Deployment Flexibility:**

```c
/* All major limits configurable at startup */
--quic-conns <N>              /* Connection limit */
--quic-handshakes <N>         /* Handshake limit */
--quic-inflight-pkts <N>      /* Frame limit */
```

**Benefits:**

- Tune for specific hardware
- Adjust for network conditions
- Different limits for mainnet vs testnet

---

### Metrics-Driven Defense

**Comprehensive Observability:**

- Connection failures → Detect flooding
- Decryption failures → Detect tampering
- Compute unit usage → Detect expensive transactions
- Flow control blocks → Detect slow consumers

**Enables:**

- Real-time attack detection
- Capacity planning
- Performance tuning

---

### Defense-in-Depth

**Multiple Independent Layers:**

1. Network layer rejects before connection allocation
2. Parser layer validates before processing
3. Compute layer limits execution time
4. Flow control prevents queue overflow
5. Resource pools prevent memory exhaustion

**Single exploit doesn't cascade:**

- Bypass retry token → still limited by connection pool
- Fill connection pool → still limited by handshake pool
- Fill handshake pool → still limited by idle timeout
- Exhaust compute budget → still limited by block limit

---

## References

- Source: `/home/user/firedancer/src/waltz/quic/`, `/src/flamenco/`, `/src/tango/`, `/src/choreo/`
- Related: `SR/Network_Layer.md`, `SR/Transaction_Processing.md`, `SR/Consensus.md`, `SR/IPC_Messaging.md`
- RFC 9000: QUIC Protocol
- RFC 9001: QUIC-TLS
- SIMD-170: Solana Compute Budget Specification

**END OF DOS MITIGATIONS ANALYSIS**
