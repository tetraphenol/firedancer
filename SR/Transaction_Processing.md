# Transaction Processing Pipeline - Security Analysis

**Components:** Verify, Dedup, Pack, Bank tiles
**Source:** `/home/user/firedancer/src/disco/`
**Analysis Date:** November 6, 2025

---

## Executive Summary

The transaction processing pipeline implements signature verification, deduplication, and block packing. Analysis identified **1 critical** (compute unit overflow) and **2 high-severity** issues (bundle limits, parse failures).

### Critical Findings Summary

| ID | Severity | Component | Issue | Location |
|----|----------|-----------|-------|----------|
| 1 | **CRITICAL** | Pack Tile | Compute unit overflow | `disco/pack/fd_pack.c` |
| 2 | **HIGH** | Dedup Tile | Bundle signature limit | `disco/dedup/fd_dedup_tile.c:194` |
| 3 | **HIGH** | Verify Tile | Parse failure cascade | `disco/verify/fd_verify_tile.c:118` |

---

## Pipeline Architecture

```
┌─────────┐   ┌─────────┐   ┌────────┐   ┌─────────┐
│   NET   │──▶│  QUIC   │──▶│ VERIFY │──▶│  DEDUP  │
└─────────┘   └─────────┘   └────────┘   └─────────┘
 Raw packets   TLS decrypt   ED25519 sig   Sig cache
               Parse txn     verification   lookup
                                                │
                                                ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐
│  STORE   │◀─│   POH    │◀─│   BANK   │◀─│  PACK   │
└──────────┘  └──────────┘  └──────────┘  └─────────┘
  To disk      Hash mixing   Execute txn   Schedule &
                                           pack block
```

---

## Signature Verification (VERIFY Tile)

### Location

**Source:** `/home/user/firedancer/src/disco/verify/`

### Architecture

- **Input:** Transactions from QUIC tile (via mcache/dcache)
- **Processing:** 
  1. Parse transaction structure
  2. Extract signatures and public keys
  3. Batch verify ED25519 signatures (up to 16 per batch)
- **Output:** Verified transactions to DEDUP tile

### HIGH: Parse Failure Cascade

**File:** `fd_verify_tile.c`, Lines 117-119

```c
txnm->txn_t_sz = (ushort)fd_txn_parse(
  fd_txn_m_payload( txnm ),
  txnm->payload_sz,
  txnt,
  NULL
);
```

**Issue:**
- `fd_txn_parse()` returns 0 on failure
- `txn_t_sz = 0` but processing continues
- Downstream dedup uses uninitialized `signature_off`

**Attack Scenario:**
```c
// Malformed transaction
txn_parse() → returns 0 (failure)
txnm->txn_t_sz = 0;
// But tile continues processing

// Dedup tile tries to read signature
sig_off = txnt->signature_off;  // Uninitialized!
memcpy(sig_cache_key, payload + sig_off, 64);  // OOB read
```

**Impact:**
- Out-of-bounds memory read
- Uninitialized data used for dedup
- Potential crash or incorrect dedup

**Recommendation:**
```c
ushort txn_sz = (ushort)fd_txn_parse(...);
if( FD_UNLIKELY( !txn_sz ) ) {
  /* Drop transaction, don't forward */
  metrics->parse_fail_cnt++;
  continue;
}
txnm->txn_t_sz = txn_sz;
```

---

### Signature Cache

**Purpose:** Avoid re-verifying recently seen signatures

**Size:** `signature_cache_size = 4194302` (default, ~4M entries)

**Mechanism:**
1. Hash signature → cache key
2. Lookup in cache
3. If found, skip verification
4. If not found, verify and insert

**Security:**
- ✅ Prevents replay attacks (signatures cached)
- ✅ DoS mitigation (avoids duplicate verification work)

---

## Deduplication (DEDUP Tile)

### Location

**Source:** `/home/user/firedancer/src/disco/dedup/`

### Architecture

- **Input:** Verified transactions
- **Processing:** 
  1. Extract transaction signature
  2. Lookup in signature cache (bloom filter + hash table)
  3. Filter duplicates
- **Output:** Unique transactions to PACK tile

### HIGH: Bundle Signature Limit

**File:** `fd_dedup_tile.c`, Lines 42-45, 194

```c
/* Only 4 signatures tracked per bundle */
uchar bundle_signatures[ 4UL ][ 64UL ];

/* Line 194: Error if >4 */
if( FD_UNLIKELY( ctx->bundle_idx > 4UL ) ) {
  FD_LOG_ERR(( "bundle_idx %lu > 4", ctx->bundle_idx ));
}
```

**Issue:**
- Hardcoded limit of 4 signatures per bundle
- Bundles with >4 transactions fail deduplication
- Potential double-spend if bundle integrity checks miss duplicates

**Attack Scenario:**
```
1. Create bundle with 5 transactions
2. Include duplicate transaction signatures
3. Bundle bypasses dedup (>4 limit exceeded)
4. If bundle validator doesn't catch duplicates:
   → Duplicate transactions executed
   → Double-spend possible
```

**Impact:**
- Transaction replay attacks
- Double-spend in bundles
- Consensus violation

**Recommendation:**
```c
/* Dynamic allocation or higher static limit */
#define MAX_BUNDLE_SIGNATURES 64
uchar bundle_signatures[ MAX_BUNDLE_SIGNATURES ][ 64UL ];

/* Validate bundle size before dedup */
if( bundle_txn_cnt > MAX_BUNDLE_SIGNATURES ) {
  return FD_DEDUP_ERR_BUNDLE_TOO_LARGE;
}
```

---

### Gossip Vote Handling

**File:** `fd_dedup_tile.c`, Lines 113-120

```c
if( FD_UNLIKELY( ctx->in_kind[ in_idx ] == IN_KIND_GOSSIP ) ) {
  if( FD_UNLIKELY( sz > FD_TPU_RAW_MTU ) ) FD_LOG_ERR(...);
  fd_memcpy( dst, src, sz );
  // No additional validation of vote transaction structure
}
```

**Issue:**
- Gossip votes bypass full bundle dedup logic
- Malformed gossip votes could cause parser failures

**Impact:** LOW-MEDIUM
- Malformed votes rejected downstream
- Parser robustness depends on vote structure validation

---

## Block Packing (PACK Tile)

### Location

**Source:** `/home/user/firedancer/src/disco/pack/`

### Architecture

- **Input:** Unique, verified transactions
- **Processing:**
  1. Maintain pending transaction pool
  2. Estimate compute units per transaction
  3. Schedule transactions for block
  4. Pack according to strategy (perf/balanced/revenue)
- **Output:** Scheduled transactions to BANK tile

### CRITICAL: Compute Unit Overflow

**File:** `fd_pack.c`

```c
/* Transaction cost estimate */
uint compute_est;  /* 32-bit value */

/* Accumulate block cost */
pack->cumulative_block_cost += cur->compute_est;  /* No overflow check */
```

**Issue:**
- `compute_est` is 32-bit unsigned
- Cumulative cost uses 64-bit unsigned
- No validation that addition doesn't overflow
- Integer wrapping possible

**Attack Scenario:**
```c
// Block limit: 48M CU
// Transaction reports: compute_est = 0xFFFFFFFF (4.2B CU)

pack->cumulative_block_cost = 40_000_000;
pack->cumulative_block_cost += 0xFFFFFFFF;  // Wraps around
// Result: Small value, appears under limit

// More transactions packed beyond limit
→ Block exceeds consensus CU limit
→ Consensus violation if different validators compute differently
```

**Impact:**
- Block cost limits exceeded
- Consensus divergence
- Network fork risk

**Recommendation:**
```c
/* Checked addition */
if( FD_UNLIKELY( pack->cumulative_block_cost > ULONG_MAX - cur->compute_est ) ) {
  /* Overflow would occur */
  return FD_PACK_ERR_COST_OVERFLOW;
}
pack->cumulative_block_cost += cur->compute_est;

/* Also validate compute_est is reasonable */
#define MAX_TXN_COMPUTE_EST (1400000UL)
if( FD_UNLIKELY( cur->compute_est > MAX_TXN_COMPUTE_EST ) ) {
  return FD_PACK_ERR_INVALID_ESTIMATE;
}
```

---

### Block Stuffing Attack

**File:** `fd_pack_tile.c`, Lines 160-166

```c
const ulong CUS_PER_MICROBLOCK = 1600000UL;  /* Per microblock limit */
```

**Issue:**
- Pack produces multiple microblocks per slot
- Each microblock has 1.6M CU limit
- No validation of cumulative cost across all microblocks in slot

**Attack:**
```
Malicious leader:
1. Pack 1.6M CU transactions per microblock
2. Create many microblocks (e.g., 50)
3. Total: 50 * 1.6M = 80M CU
4. Exceeds slot limit (48M CU)
```

**Impact:**
- Slot limits exceeded
- Other validators reject block
- Leader slot wasted

**Recommendation:**
```c
/* Track cumulative slot cost */
slot->cumulative_slot_cost += microblock->cost;

if( slot->cumulative_slot_cost > SLOT_COST_LIMIT ) {
  return FD_PACK_ERR_SLOT_LIMIT_EXCEEDED;
}
```

---

### Compute Budget Program

**File:** `fd_compute_budget_program.h`, Lines 20-28

**Purpose:** Parse compute budget instructions to determine transaction cost

**Issue:**
- Cost estimation depends on BPF program analysis
- Actual execution cost may differ from estimate

**Attack:**
```
1. Program requests low compute budget (e.g., 10K CU)
2. Pack tile estimates 10K CU
3. Actual execution uses 100K CU
4. Transaction aborted mid-execution
```

**Impact:** LOW
- Transaction fails, fees collected
- No consensus violation
- DoS if many such transactions

---

### Write-Lock Cost Tracking

**File:** `fd_pack.c`

```c
/* Per-account write cost limit */
if( FD_UNLIKELY(
  in_wcost_table &&
  in_wcost_table->total_cost + cur->compute_est > max_write_cost_per_acct
) ) {
  /* Reject transaction */
}
```

**Issue:**
- Cost estimates may be inaccurate
- If estimate too low, write-lock limit can be exceeded

**Impact:** MEDIUM
- Hotspot accounts over-utilized
- Performance degradation
- Mitigated by actual CU metering during execution

---

## Transaction Execution (BANK Tile)

### Location

**Source:** Agave validator (not Firedancer implementation yet)

### Interface

**Frankendancer:** Firedancer packs transactions, Agave executes

**Security Boundaries:**
1. Pack provides ordered transactions
2. Agave validates and executes
3. Results returned to Firedancer for PoH mixing

### Compute Unit Enforcement

**Agave Runtime:**
- Meters BPF instructions
- Enforces CU limits
- Aborts transactions exceeding limits

**Defense in Depth:**
- Pack estimates CU
- Bank enforces actual CU
- Double validation

---

## Recommendations

### Critical (Immediate)

1. **Fix Compute Unit Overflow** (`fd_pack.c`)
   - Add overflow check before accumulation
   - Validate individual transaction estimates

2. **Add Slot-Wide Cost Tracking**
   - Track cumulative cost across all microblocks
   - Enforce slot limit

### High Priority

3. **Increase Bundle Signature Capacity** (`fd_dedup_tile.c`)
   - Raise limit to 64 or make dynamic
   - Add comprehensive bundle validation

4. **Fix Parse Failure Handling** (`fd_verify_tile.c`)
   - Drop transactions with parse errors
   - Don't forward to dedup

5. **Add Compute Estimate Validation**
   - Maximum reasonable estimate per transaction
   - Reject obviously invalid estimates

### Medium Priority

6. **Improve Write-Lock Cost Tracking**
   - More accurate cost estimation
   - Dynamic adjustment based on actual execution

7. **Add Bundle Integrity Checks**
   - Validate bundle structure before dedup
   - Comprehensive duplicate detection

---

## Testing Recommendations

### Fuzzing

1. **Transaction Parser**
   - Malformed transactions
   - Boundary conditions
   - Invalid signatures

2. **Cost Estimation**
   - Edge case compute budgets
   - Overflow values
   - Negative costs

### Adversarial Testing

1. **Bundle Attacks**
   - >4 signature bundles
   - Duplicate transactions in bundle
   - Invalid bundle structures

2. **Block Stuffing**
   - Maximum microblocks per slot
   - Cumulative cost tracking
   - Overflow scenarios

---

## References

- Source: `/home/user/firedancer/src/disco/`
- Related: `SR/Architecture.md`, `SR/sBPF_VM_Runtime.md`

**END OF TRANSACTION PROCESSING ANALYSIS**
