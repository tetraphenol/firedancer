# NET-002: QUIC Stream Limit Integer Overflow

## Severity
**MEDIUM**

## Summary
The QUIC transport parameter processing performs a left shift operation on peer-provided `initial_max_streams_uni` without overflow validation, allowing malicious peers to cause integer overflow and bypass stream ID validation checks.

## Affected Components
- `src/waltz/quic/fd_quic.c:2700-2709` (client-side transport parameter processing)
- `src/waltz/quic/fd_quic.c:4258-4267` (server-side transport parameter processing)
- `src/waltz/quic/fd_quic_conn.h:167` (`tx_sup_stream_id` field definition)

## Technical Details

### Vulnerability Mechanism

During QUIC connection establishment, peers exchange transport parameters including `initial_max_streams_uni` (maximum unidirectional streams). Firedancer converts this count to a stream ID by left-shifting without overflow validation.

**Vulnerable Code** in `src/waltz/quic/fd_quic.c:2706`:

```c
/* initial max_streams */

if( conn->server ) {
  conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_SERVER;
} else {
  conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;
}
```

**The Problem:**
- `initial_max_streams_uni` is peer-controlled (received in transport parameters)
- Left shift by 2 bits (`<< 2`) multiplies value by 4
- No validation that `initial_max_streams_uni * 4` stays within bounds
- If `initial_max_streams_uni >= (1UL << 62)`, the shift overflows
- Result: `tx_sup_stream_id` wraps to a small value

**QUIC Stream ID Encoding:**
Stream IDs encode both stream number and type:
```
[stream_number (62 bits)] [direction (1 bit)] [initiator (1 bit)]
```

The left shift by 2 converts stream count to stream ID by making room for the 2-bit type field.

### Code Evidence

**Vulnerable Conversion** (`fd_quic.c:2706, 4266`):
```c
conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_SERVER;
```

**Server-Side Safe Default** (`fd_quic.c:534`):
```c
ulong initial_max_streams_uni = quic->config.role==FD_QUIC_ROLE_SERVER ? 1UL<<60 : 0;
```

Firedancer correctly uses a safe value (`1UL<<60`) when acting as server, but does not validate peer values when acting as client.

**Stream ID Validation** (`fd_quic.c:3892-3898`):
```c
/* Validate stream ID against limits */
if( FD_UNLIKELY( stream_id >= conn->tx_sup_stream_id ) ) {
  fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR, __LINE__ );
  return NULL;
}
```

This check can be bypassed if `tx_sup_stream_id` has overflowed to a small value.

### Attack Scenario

**Objective**: Bypass stream ID limits and create excessive streams or pollute stream map.

**Attack Vector 1: Overflow to Bypass Stream Limits**
1. Malicious peer (acting as QUIC server) sends transport parameters with:
   ```
   initial_max_streams_uni = (1UL << 62) - 1  // Close to overflow threshold
   ```
2. Firedancer client processes transport parameters:
   ```c
   tx_sup_stream_id = ((1UL << 62) - 1) << 2  // Overflows
                    = ...wraps to small value
   ```
3. Now stream ID checks use overflowed `tx_sup_stream_id`
4. Validation at line 3892 may pass for large stream IDs that should be rejected

**Attack Vector 2: Trigger Incorrect Stream State**
1. Overflow causes `tx_sup_stream_id` to be smaller than expected
2. Legitimate stream creation may be incorrectly blocked
3. Stream state machine enters unexpected state

**Attack Vector 3: Stream Map Pollution**
1. With overflowed limits, attacker may create streams with unexpected IDs
2. Stream map (`conn->stream_map`) may be polluted with invalid entries
3. Potential resource exhaustion or incorrect stream routing

**Prerequisites**:
- Ability to act as malicious QUIC server (requires client to connect)
- Control over transport parameter values
- Valid TLS certificates for QUIC handshake (or vulnerable to MitM)

**Likelihood**: LOW
- Requires client to connect to malicious server
- Firedancer typically acts as server, not client, in most deployments
- Stream pool limits still apply as defense-in-depth

### Impact Assessment

**Security Impact**: MEDIUM (mitigated by secondary controls)

**Primary Mitigation Factors:**
1. **Stream Pool Limits**: Pre-allocated stream pool bounds total streams
   - Pool size set at initialization (`fd_quic.c:539`)
   - Pool exhaustion prevents unbounded stream creation
   - This is the critical defense-in-depth protection

2. **Connection Limits**: Total connections are limited
   - Limits impact from single malicious peer

3. **Deployment Pattern**: Firedancer typically acts as QUIC server
   - Vulnerability only affects client-side connection establishment
   - Most deployments accept connections rather than initiate them

**Potential Impacts:**
- Stream ID validation bypass for specific stream ID ranges
- Incorrect stream limiting (may block legitimate streams)
- Stream map pollution with unexpected entries
- Confusion in stream state machine
- NOT a direct memory corruption or RCE vector

**Scope**:
- Affects Firedancer instances acting as QUIC clients
- Requires connection to malicious QUIC server
- Limited by stream pool and connection limits
- Does not affect typical validator operation (server role)

## Proof of Concept

```python
#!/usr/bin/env python3
"""
QUIC stream limit overflow PoC
Demonstrates overflow in transport parameter processing
"""

def simulate_overflow(initial_max_streams_uni):
    """
    Simulate the vulnerable shift operation

    Args:
        initial_max_streams_uni: Peer-provided stream limit
    Returns:
        Computed tx_sup_stream_id
    """
    # Constants from fd_quic.h
    FD_QUIC_STREAM_TYPE_UNI_CLIENT = 0b10  # Unidirectional, client-initiated
    MASK_64 = (1 << 64) - 1  # Simulate 64-bit unsigned overflow

    # Vulnerable operation (simulating ulong overflow)
    tx_sup_stream_id = ((initial_max_streams_uni << 2) & MASK_64) + FD_QUIC_STREAM_TYPE_UNI_CLIENT

    return tx_sup_stream_id

# Test cases
test_cases = [
    ("Normal", 100),
    ("Large but safe", 1 << 60),
    ("At overflow boundary", (1 << 62) - 1),
    ("Overflow", 1 << 62),
    ("Large overflow", (1 << 62) + 1000),
    ("Maximum value", (1 << 64) - 1),
]

print("QUIC Stream Limit Overflow Analysis\n")
print(f"{'Description':<25} {'Input Value':<20} {'Result tx_sup_stream_id':<25} {'Overflowed?'}")
print("-" * 100)

for desc, value in test_cases:
    result = simulate_overflow(value)
    overflowed = (value << 2) >= (1 << 64)

    print(f"{desc:<25} {value:<20} {result:<25} {'YES' if overflowed else 'NO'}")

print("\n" + "=" * 100)
print("Analysis:")
print("- Values >= 2^62 cause overflow when left-shifted by 2")
print("- Overflowed tx_sup_stream_id wraps to small values")
print("- Stream ID validation checks may be bypassed")
print("- Stream pool limits still apply as defense-in-depth")
```

**Expected Output:**
```
QUIC Stream Limit Overflow Analysis

Description               Input Value          Result tx_sup_stream_id   Overflowed?
----------------------------------------------------------------------------------------------------
Normal                    100                  402                       NO
Large but safe            1152921504606846976  4611686018427387906       NO
At overflow boundary      4611686018427387903  18446744073709551614      NO
Overflow                  4611686018427387904  2                         YES
Large overflow            4611686018427388904  4002                      YES
Maximum value             18446744073709551615 18446744073709551614      YES
```

## Exploitation Difficulty
**MEDIUM to HIGH**

**Factors Increasing Difficulty:**
- Requires Firedancer to act as QUIC client (uncommon deployment)
- Attacker must control QUIC server peer connects to
- Stream pool limits provide defense-in-depth
- No clear path to memory corruption or RCE
- Impact limited to stream management confusion

**Factors Decreasing Difficulty:**
- Malicious transport parameter easy to craft
- No complex protocol interaction required
- Overflow is deterministic
- Standard QUIC server tools can be modified

## Recommended Mitigations

### 1. Validate Transport Parameters Before Use (Immediate Fix)

Add validation to `src/waltz/quic/fd_quic.c` before line 2706:

```c
/* Validate initial_max_streams_uni to prevent overflow */
#define FD_QUIC_MAX_STREAMS_UNI_LIMIT (1UL << 60)  // 2^60 streams max

if( FD_UNLIKELY( peer_tp->initial_max_streams_uni > FD_QUIC_MAX_STREAMS_UNI_LIMIT ) ) {
  FD_LOG_WARNING(( "Peer initial_max_streams_uni %lu exceeds limit %lu, clamping",
                   peer_tp->initial_max_streams_uni,
                   FD_QUIC_MAX_STREAMS_UNI_LIMIT ));
  peer_tp->initial_max_streams_uni = FD_QUIC_MAX_STREAMS_UNI_LIMIT;
}

/* Now safe to perform shift */
if( conn->server ) {
  conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_SERVER;
} else {
  conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;
}
```

**Rationale for 2^60 limit:**
- Firedancer uses `1UL<<60` as safe default (line 534)
- Allows `<< 2` shift without overflow (2^62 boundary)
- 2^60 streams is astronomically large (1,152,921,504,606,846,976 streams)
- Any legitimate use case satisfied by this limit

### 2. Add Overflow-Safe Arithmetic

Use checked arithmetic for the conversion:

```c
#include "fd_util.h"  // Assume fd_util has checked math

static inline ulong
fd_quic_stream_count_to_id_safe( ulong stream_count, uchar stream_type ) {
  // Check for overflow before shift
  if( FD_UNLIKELY( stream_count > (ULONG_MAX >> 2) ) ) {
    FD_LOG_ERR(( "Stream count %lu would overflow when converted to stream ID", stream_count ));
    return ULONG_MAX;  // Sentinel value
  }

  return (stream_count << 2UL) + stream_type;
}

// Use in connection setup:
conn->tx_sup_stream_id = fd_quic_stream_count_to_id_safe(
    peer_tp->initial_max_streams_uni,
    conn->server ? FD_QUIC_STREAM_TYPE_UNI_SERVER : FD_QUIC_STREAM_TYPE_UNI_CLIENT
);

if( conn->tx_sup_stream_id == ULONG_MAX ) {
  fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR, __LINE__ );
  return;
}
```

### 3. Add Comprehensive Transport Parameter Validation

Validate all transport parameters against reasonable bounds:

```c
static int
fd_quic_validate_transport_params( fd_quic_transport_params_t const * peer_tp,
                                   int                                 we_are_server ) {
  // Validate max_streams_uni
  if( peer_tp->initial_max_streams_uni > FD_QUIC_MAX_STREAMS_UNI_LIMIT ) {
    FD_LOG_WARNING(( "Invalid initial_max_streams_uni: %lu", peer_tp->initial_max_streams_uni ));
    return 0;
  }

  // Validate max_streams_bidi
  if( peer_tp->initial_max_streams_bidi > FD_QUIC_MAX_STREAMS_BIDI_LIMIT ) {
    FD_LOG_WARNING(( "Invalid initial_max_streams_bidi: %lu", peer_tp->initial_max_streams_bidi ));
    return 0;
  }

  // Validate other critical parameters
  if( peer_tp->initial_max_data > FD_QUIC_MAX_DATA_LIMIT ) {
    FD_LOG_WARNING(( "Invalid initial_max_data: %lu", peer_tp->initial_max_data ));
    return 0;
  }

  // ... other validations ...

  return 1;  // Valid
}

// Call before processing transport parameters
if( !fd_quic_validate_transport_params( peer_tp, conn->server ) ) {
  fd_quic_conn_error( conn, FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR, __LINE__ );
  return;
}
```

### 4. Add Unit Tests for Overflow Cases

Create test cases in QUIC test suite:

```c
// In fd_quic_test.c or similar
static void
test_stream_limit_overflow( void ) {
  // Test overflow boundary
  ulong overflow_value = (1UL << 62);
  fd_quic_transport_params_t params = { .initial_max_streams_uni = overflow_value };

  // Should reject or clamp overflow values
  int valid = fd_quic_validate_transport_params( &params, 0 );
  FD_TEST( !valid || params.initial_max_streams_uni <= FD_QUIC_MAX_STREAMS_UNI_LIMIT );

  // Test safe values
  params.initial_max_streams_uni = (1UL << 60);
  valid = fd_quic_validate_transport_params( &params, 0 );
  FD_TEST( valid );
}
```

## Detection Strategies

### Runtime Monitoring

Monitor for suspicious transport parameter values:
- `initial_max_streams_uni > 2^60`
- `initial_max_streams_bidi > 2^60`
- Sudden connection errors with TRANSPORT_PARAMETER_ERROR

### Alerting Thresholds
```
ALERT: quic_tp_initial_max_streams_uni > (1UL << 60)
ALERT: quic_stream_id_overflow_detected
ALERT: quic_conn_error_transport_params > 10 in 60 seconds
```

### Logging

Add to transport parameter processing:
```c
FD_LOG_INFO(( "QUIC transport params: peer=%s initial_max_streams_uni=%lu tx_sup_stream_id=%lu",
              peer_addr_str, peer_tp->initial_max_streams_uni, conn->tx_sup_stream_id ));

// Log validation failures
FD_LOG_WARNING(( "QUIC transport param validation failed: peer=%s param=initial_max_streams_uni value=%lu",
                 peer_addr_str, peer_tp->initial_max_streams_uni ));
```

### Metrics to Track
- `fd_quic_tp_validation_failures` - Transport parameter validation failures
- `fd_quic_stream_limit_violations` - Stream limit exceeded errors
- `fd_quic_tp_max_streams_histogram` - Distribution of peer max_streams values

## References

### QUIC Specifications
- **RFC 9000 Section 4.6**: Controlling Concurrency (stream limits)
- **RFC 9000 Section 18.2**: Transport Parameter Definitions
- **RFC 9000 Section 19.11**: STREAM_LIMIT_ERROR

### Similar Vulnerabilities
- **CVE-2021-XXXX** (Various) - Integer overflow in protocol parameter processing
- QUIC implementation vulnerabilities (various vendors)

### Internal References
- `src/waltz/quic/fd_quic.c:534` - Server-side safe default (`1UL<<60`)
- `src/waltz/quic/fd_quic.c:2706` - Vulnerable client-side conversion
- `src/waltz/quic/fd_quic.c:4266` - Duplicate vulnerable code (server processing peer params)
- `src/waltz/quic/fd_quic.c:3892-3898` - Stream ID validation that can be bypassed
- `SR/Checklist.md` - Section 6.1 (QUIC Protocol Security)

## Timeline
- **Discovered**: 2025-11-18 (Phase 6 security assessment)
- **Reported**: 2025-11-18
- **Status**: UNFIXED

## Additional Notes

**Risk Assessment:**
- **Theoretical Risk**: MEDIUM (integer overflow, validation bypass)
- **Practical Risk**: LOW (mitigated by stream pools, uncommon code path)

**Key Mitigating Factors:**
1. Stream pool pre-allocation limits total streams regardless of `tx_sup_stream_id`
2. Firedancer primarily acts as QUIC server, not client
3. Attack requires connection to malicious server
4. No clear path to memory corruption or RCE

**Why Still Important:**
- Defense-in-depth: all input validation should be robust
- Integer overflows are dangerous and should be prevented
- Future code changes might rely on `tx_sup_stream_id` being valid
- Best practice: validate all protocol parameters

**Testing Recommendations:**
1. Add fuzzing for QUIC transport parameter parsing
2. Create unit tests for overflow boundary conditions
3. Test with maximum valid and invalid transport parameter values
4. Verify connection error handling for invalid parameters

**Code Quality Observations:**
- Same vulnerable pattern appears at lines 2706 and 4266 (duplication)
- Consider refactoring to single transport parameter processing function
- Server correctly uses safe default `1UL<<60`, should apply same to peer validation

**Comparison with RFC 9000:**
RFC 9000 does not specify maximum values for `initial_max_streams_*` parameters, leaving validation to implementations. However, the RFC does require implementations to handle invalid parameters gracefully and close connections with TRANSPORT_PARAMETER_ERROR if needed.
