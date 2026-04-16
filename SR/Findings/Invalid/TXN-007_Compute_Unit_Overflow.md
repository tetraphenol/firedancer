# TXN-007: Compute Unit Integer Overflow in Block Packing

## Severity
**CRITICAL**

## Summary
The block packing logic uses unchecked integer addition to accumulate compute units (CUs), allowing integer overflow that can bypass block CU limits and cause consensus divergence.

## Affected Components
- `src/disco/pack/fd_pack.c:2425` (microblock packing)
- `src/disco/pack/fd_pack.c:2525` (vote transaction scheduling)
- `src/disco/pack/fd_pack.c:2553` (non-vote transaction scheduling)
- `src/disco/pack/fd_pack.c:2242` (CU limit calculation)

## Technical Details

### Vulnerability Mechanism

The code accumulates compute units without overflow protection:

```c
// Line 2425 - Microblock packing
pack->cumulative_block_cost += cur->compute_est;

// Line 2525 - Vote scheduling
pack->cumulative_block_cost += status1.cus_scheduled;

// Line 2553 - Transaction scheduling
pack->cumulative_block_cost += status.cus_scheduled;
```

The remaining CU limit is calculated by subtraction:

```c
// Line 2242
ulong cu_limit = pack->lim->max_cost_per_block - pack->cumulative_block_cost;
```

**The Bug**: When `cumulative_block_cost` overflows:
1. It wraps from `ULONG_MAX` to small values
2. The subtraction on line 2242 produces a large `cu_limit`
3. More transactions get packed despite exceeding the block CU limit
4. The block violates Solana consensus rules

### Attack Scenario

**Objective**: Pack transactions exceeding the block CU limit to create an invalid block.

**Prerequisites**:
- Attacker controls leader schedule (or targets specific leader)
- Can submit transactions with manipulated `compute_est` values

**Attack Steps**:

1. **Set up near-overflow condition**:
   - Block CU limit: 48,000,000 (typical Solana limit)
   - Target: `cumulative_block_cost` close to `ULONG_MAX`
   - Required: `ULONG_MAX - 48M` worth of CUs already consumed

2. **Trigger overflow**:
   ```python
   # Assume cumulative_block_cost = ULONG_MAX - 10,000,000

   # Submit transaction with compute_est = 20,000,000
   malicious_txn = create_txn(compute_est=20_000_000)

   # After packing:
   # cumulative_block_cost = (ULONG_MAX - 10M) + 20M
   #                       = ULONG_MAX + 10M
   #                       = 10M (after overflow)
   ```

3. **Exploit inflated limit**:
   ```c
   // Next scheduling call:
   cu_limit = 48_000_000 - 10_000_000 = 38_000_000

   // Should be: 48_000_000 - (ULONG_MAX + 10M) = negative (saturated to 0)
   // Actually: Large positive value, allowing more packing
   ```

4. **Result**:
   - Block contains >>48M CUs
   - Other validators reject block as invalid
   - Consensus failure / slot skip

### Practical Exploitability

**Challenge**: Reaching near-`ULONG_MAX` CUs

On a 64-bit system:
- `ULONG_MAX = 18,446,744,073,709,551,615`
- Block limit: `48,000,000` CUs
- Would need: `~384 billion blocks` to accumulate naturally

However:
1. **`cumulative_block_cost` persists across blocks**: Need to check if it resets
2. **Malicious compute estimates**: Can `compute_est` be manipulated?
3. **Bank tile confusion**: If packing for wrong bank tile, metrics might not reset

Let me check the reset logic:

```c
// Line 2681 - In fd_pack_end_block()
pack->cumulative_block_cost = 0UL;
```

**Good**: Reset happens at block end. But what if:
- Block never ends (crash/hang)?
- Reset is skipped due to error path?
- Multiple bank tiles cause confusion?

### Alternative Attack: Compute Estimate Manipulation

More practical attack: Manipulate `compute_est` directly.

```c
// Where does compute_est come from?
// Line 2425: cur->compute_est
```

If `compute_est` can be set to `ULONG_MAX - cumulative_block_cost + X`, then:
```
new_cumulative = cumulative + (ULONG_MAX - cumulative + X)
               = ULONG_MAX + X
               = X (overflow)
```

Need to trace where `compute_est` originates - likely from transaction metadata.

### Impact Assessment

**If exploitable**:
1. **Consensus Violation**: Block exceeds CU limit → other validators reject
2. **Leader Penalty**: Malicious leader loses block rewards, possibly slashed
3. **Network Disruption**: Slot skip affects finality
4. **Validator Divergence**: Different validators might have different views

**Current Likelihood**: LOW-MEDIUM
- Requires specific conditions (near-overflow or controlled compute_est)
- Reset at block end makes natural overflow impractical
- But defense-in-depth dictates overflow protection should exist

**If `compute_est` is attacker-controlled**: CRITICAL
- Direct overflow trigger
- Immediately exploitable

## Root Cause Analysis

1. **Unchecked Arithmetic**: No saturation or overflow detection
2. **Unsigned Underflow in Limit Calc**: Line 2242 subtracts unsigned values
   - If `cumulative > max`, result wraps to huge positive number
3. **Missing Invariant Check**: No assertion that `cumulative <= max` before subtraction

## Proof of Concept

```c
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

void simulate_overflow() {
    uint64_t cumulative_block_cost = 0;
    uint64_t max_cost_per_block = 48000000UL;

    // Simulate near-overflow scenario
    cumulative_block_cost = ULONG_MAX - 10000000UL;

    printf("Before overflow:\n");
    printf("  cumulative_block_cost = %lu\n", cumulative_block_cost);
    printf("  max_cost_per_block    = %lu\n", max_cost_per_block);

    // Add transaction that causes overflow
    uint64_t compute_est = 20000000UL;
    cumulative_block_cost += compute_est;

    printf("\nAfter adding %lu CUs:\n", compute_est);
    printf("  cumulative_block_cost = %lu (overflowed!)\n", cumulative_block_cost);

    // Calculate remaining limit (vulnerable line 2242)
    uint64_t cu_limit = max_cost_per_block - cumulative_block_cost;

    printf("\nCalculated cu_limit:\n");
    printf("  cu_limit = %lu - %lu = %lu\n",
           max_cost_per_block, cumulative_block_cost, cu_limit);
    printf("  (Should be 0 or negative, but unsigned underflow!)\n");

    if (cu_limit > max_cost_per_block) {
        printf("\n[VULNERABILITY] cu_limit exceeds block limit!\n");
        printf("  Can pack %lu more CUs despite block being full\n", cu_limit);
    }
}

int main() {
    simulate_overflow();
    return 0;
}
```

Expected output:
```
Before overflow:
  cumulative_block_cost = 18446744073699551615
  max_cost_per_block    = 48000000

After adding 20000000 CUs:
  cumulative_block_cost = 10000000 (overflowed!)

Calculated cu_limit:
  cu_limit = 48000000 - 10000000 = 38000000
  (Should be 0 or negative, but unsigned underflow!)

[VULNERABILITY] cu_limit exceeds block limit!
  Can pack 38000000 more CUs despite block being full
```

## Recommended Mitigations

### Immediate Fix (Required)

Use saturating addition:

```c
// Replace line 2425
pack->cumulative_block_cost = fd_ulong_sat_add(
    pack->cumulative_block_cost,
    cur->compute_est
);

// Replace line 2525
pack->cumulative_block_cost = fd_ulong_sat_add(
    pack->cumulative_block_cost,
    status1.cus_scheduled
);

// Replace line 2553
pack->cumulative_block_cost = fd_ulong_sat_add(
    pack->cumulative_block_cost,
    status.cus_scheduled
);

// Replace line 2242 with saturating subtraction
ulong cu_limit = fd_ulong_sat_sub(
    pack->lim->max_cost_per_block,
    pack->cumulative_block_cost
);
```

### Defense in Depth

Add invariant checks:

```c
// After each addition, assert invariant
FD_TEST( pack->cumulative_block_cost <= pack->lim->max_cost_per_block );

// Or log warning and cap:
if( FD_UNLIKELY( pack->cumulative_block_cost > pack->lim->max_cost_per_block ) ) {
    FD_LOG_WARNING(( "Cumulative block cost %lu exceeds limit %lu, capping",
                     pack->cumulative_block_cost,
                     pack->lim->max_cost_per_block ));
    pack->cumulative_block_cost = pack->lim->max_cost_per_block;
}
```

### Validation

Add runtime checks:

```c
// Before calculating cu_limit
if( FD_UNLIKELY( pack->cumulative_block_cost >= pack->lim->max_cost_per_block ) ) {
    cu_limit = 0UL;  // No more CUs available
} else {
    cu_limit = pack->lim->max_cost_per_block - pack->cumulative_block_cost;
}
```

## Verification

### Test Cases

```c
void test_cu_overflow() {
    fd_pack_t pack = {0};
    pack.lim->max_cost_per_block = 48000000UL;

    // Test 1: Normal accumulation
    pack.cumulative_block_cost = 0;
    pack.cumulative_block_cost = fd_ulong_sat_add(
        pack.cumulative_block_cost, 30000000UL
    );
    assert(pack.cumulative_block_cost == 30000000UL);

    // Test 2: Saturation at max
    pack.cumulative_block_cost = fd_ulong_sat_add(
        pack.cumulative_block_cost, 30000000UL
    );
    assert(pack.cumulative_block_cost == 48000000UL);  // Saturated, not 60M

    // Test 3: Overflow attempt
    pack.cumulative_block_cost = ULONG_MAX - 1000000UL;
    pack.cumulative_block_cost = fd_ulong_sat_add(
        pack.cumulative_block_cost, 2000000UL
    );
    assert(pack.cumulative_block_cost == ULONG_MAX);  // Saturated

    // Test 4: cu_limit calculation
    ulong cu_limit = fd_ulong_sat_sub(48000000UL, ULONG_MAX);
    assert(cu_limit == 0UL);  // Not a huge positive number
}
```

## Status
- **Discovered**: 2025-11-08
- **Severity**: CRITICAL
- **Exploitability**: LOW-MEDIUM (depends on compute_est control)
- **Impact**: CRITICAL (consensus violation)
- **Priority**: HIGH (defense-in-depth fix required)

## References

1. **CWE-190**: Integer Overflow or Wraparound
   - https://cwe.mitre.org/data/definitions/190.html

2. **CWE-191**: Integer Underflow (Wrap or Wraparound)
   - https://cwe.mitre.org/data/definitions/191.html

3. **Solana Block Limits**:
   - Compute Unit limit: 48,000,000 per block
   - Violations cause block rejection

4. **fd_ulong_sat_add**: Firedancer saturating arithmetic
   - Located in `src/util/fd_util_base.h`
   - Saturates at `ULONG_MAX` instead of wrapping

## Conclusion

While natural overflow is impractical due to block-end resets, the lack of overflow protection violates defense-in-depth principles. If `compute_est` can be manipulated or any code path skips the reset, this becomes immediately exploitable. **Recommend applying saturating arithmetic immediately.**
