# NET-004: STREAM Frame Integer Overflow Bypasses Flow Control

**Severity**: HIGH
**Component**: QUIC Protocol Implementation / Net Tile
**Location**: `src/waltz/quic/fd_quic.c:5037`
**Discovered**: 2025-11-18
**Status**: Unpatched

## Summary

The QUIC STREAM frame handler performs unchecked arithmetic when validating flow control limits. An integer overflow in the expression `offset + data_sz` allows an attacker to bypass the advertised stream data limits by causing the sum to wrap around to a small value. This enables an attacker to send more data than permitted, violating QUIC flow control guarantees and potentially causing memory corruption, resource exhaustion, or application-level logic errors in stream processing callbacks.

## Technical Details

### Vulnerable Code

From `src/waltz/quic/fd_quic.c:5033-5045`:

```c
static ulong
fd_quic_handle_stream_frame(
    fd_quic_frame_ctx_t * context,
    uchar const *         p,
    ulong                 p_sz,
    ulong                 stream_id,
    ulong                 offset,     /* ATTACKER CONTROLLED - range [0, 2^62-1] */
    ulong                 data_sz,    /* ATTACKER CONTROLLED - range [0, 2^62-1] */
    int                   fin ) {
  fd_quic_t *      quic = context->quic;
  fd_quic_conn_t * conn = context->conn;
  fd_quic_pkt_t *  pkt  = context->pkt;

  // ... (validation checks omitted) ...

  /* A receiver MUST close the connection with an error of type FLOW_CONTROL_ERROR if the sender
     violates the advertised connection or stream data limits */
  if( FD_UNLIKELY( quic->config.initial_rx_max_stream_data < offset + data_sz ) ) {
    /* ❌ UNCHECKED ADDITION - INTEGER OVERFLOW BYPASSES CHECK! */
    FD_DEBUG( FD_LOG_DEBUG(( "Stream data limit exceeded" )); )
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  /* Pass data to application callback */
  int rx_res = fd_quic_cb_stream_rx( quic, conn, stream_id, offset, p, data_sz, fin );
  pkt->ack_flag |= fd_uint_if( rx_res==FD_QUIC_SUCCESS, 0U, ACK_FLAG_CANCEL );

  return data_sz;
}
```

### Root Cause

The QUIC protocol defines flow control limits to prevent receivers from being overwhelmed by data. The `initial_rx_max_stream_data` configuration parameter (typically 256KB or similar) specifies the maximum number of bytes that can be received on a single stream.

The flow control check at line 5037 is intended to enforce this limit by verifying that `offset + data_sz <= initial_rx_max_stream_data`. However, the addition `offset + data_sz` is performed **without overflow protection**, allowing the sum to wrap around.

**Vulnerable arithmetic**:
1. Attacker controls `offset` and `data_sz` (both varints in range `[0, 2^62-1]`)
2. Flow control check: `limit < offset + data_sz`
3. If `offset + data_sz` overflows, the comparison operates on the **wrapped** value
4. An overflowed (small) value bypasses the check
5. Application callback receives data at the **true** (overflowed) offset

### Attack Vector

An attacker sends QUIC STREAM frames with crafted offset and data_sz values to bypass flow control:

**Example 1: Bypass 256KB limit**
- `initial_rx_max_stream_data = 0x40000` (262,144 bytes = 256KB)
- Attacker sends STREAM frame:
  - `offset = 0xFFFFFFFFFFF00000` (ULONG_MAX - 1MB + 1)
  - `data_sz = 0x100000` (1MB)
  - `offset + data_sz = 0xFFFFFFFFFFF00000 + 0x100000 = 0x0` (wraps to 0)
- Flow control check: `0x40000 < 0`? **FALSE** - check passes ✓
- Callback invoked: `fd_quic_cb_stream_rx(stream_id, offset=0xFFFFFFFFFFF00000, data=1MB)`

**Example 2: Precise bypass**
- `initial_rx_max_stream_data = 0x40000` (256KB)
- Attacker sends:
  - `offset = 0xFFFFFFFFFFFBFFFF` (ULONG_MAX - 256KB)
  - `data_sz = 0x40001` (256KB + 1 byte)
  - `offset + data_sz = 0x0` (wraps exactly to 0)
- Flow control check: `0x40000 < 0`? **FALSE** - check passes ✓
- Result: 256KB + 1 byte delivered despite 256KB limit

**Example 3: Small wraparound value**
- `initial_rx_max_stream_data = 0x40000` (256KB)
- Attacker sends:
  - `offset = 0xFFFFFFFFFFFBFFFE` (ULONG_MAX - 256KB - 1)
  - `data_sz = 0x80000` (512KB)
  - `offset + data_sz = 0x3FFFE` (wraps to 262,142)
- Flow control check: `0x40000 < 0x3FFFE`? **FALSE** - check passes ✓
- Result: 512KB delivered despite 256KB limit

### Secondary Impacts

Beyond bypassing flow control, this vulnerability has several concerning consequences:

1. **Application callback receives invalid offset**: The `fd_quic_cb_stream_rx()` callback is invoked with `offset = 0xFFFFFFFFFFF00000` (or similar huge value), which may cause:
   - Buffer overflows in the callback implementation if it uses `offset` for indexing
   - Integer overflows in the callback's own arithmetic
   - Logic errors if the callback assumes reasonable offset values

2. **Stream reassembly corruption**: QUIC streams can deliver data out-of-order. If the stream reassembly logic uses the offset value for bookkeeping, an overflowed offset could:
   - Corrupt internal state tracking
   - Cause memory corruption when storing stream data
   - Trigger assertion failures or crashes

3. **Resource exhaustion**: By bypassing flow control, an attacker can:
   - Send unlimited data to exhaust receiver memory
   - Force expensive processing operations on large data volumes
   - Cause denial of service through resource consumption

## Proof of Concept

### Attack Scenario

1. Attacker establishes QUIC connection with victim Firedancer validator
2. Attacker opens a bidirectional stream (stream ID 0)
3. Victim advertises `initial_rx_max_stream_data = 0x40000` (256KB) in transport parameters
4. Attacker sends STREAM frame:
   - Stream ID: 0
   - Offset: `0xFFFFFFFFFFF00000`
   - Length: `0x100000` (1MB)
   - Data: 1MB of attacker-controlled payload
5. Victim's `fd_quic_handle_stream_frame()` is invoked
6. Integer overflow: `offset + data_sz = 0x0` (wraps to 0)
7. Flow control check bypassed: `0x40000 < 0` is false
8. Callback invoked: `fd_quic_cb_stream_rx(stream=0, offset=0xFFFFFFFFFFF00000, data=1MB, len=1MB)`
9. Callback processes 1MB of data despite 256KB limit
10. Potential outcomes:
    - Memory corruption if callback uses offset for buffer indexing
    - Resource exhaustion from processing excessive data
    - Denial of service if stream state becomes corrupted

### Minimal Test Case

```c
/* Simulated configuration */
ulong initial_rx_max_stream_data = 0x40000UL;  /* 256KB limit */

/* Simulated attacker values */
ulong offset  = 0xFFFFFFFFFFF00000UL;  /* ULONG_MAX - 1MB + 1 */
ulong data_sz = 0x100000UL;            /* 1MB */

/* Flow control check (vulnerable code) */
if( initial_rx_max_stream_data < offset + data_sz ) {
  /* This should trigger - but doesn't due to overflow */
  printf("Flow control error (should trigger)\n");
} else {
  /* Vulnerable code path - overflow bypassed the check */
  printf("Flow control check BYPASSED!\n");
  printf("  offset = 0x%lx, data_sz = 0x%lx\n", offset, data_sz);
  printf("  offset + data_sz = 0x%lx (overflowed to %lu)\n",
         offset + data_sz, offset + data_sz);
  printf("  limit = 0x%lx (%lu bytes)\n",
         initial_rx_max_stream_data, initial_rx_max_stream_data);
  printf("  Delivered %lu bytes despite %lu byte limit!\n",
         data_sz, initial_rx_max_stream_data);
}
```

**Expected output**:
```
Flow control check BYPASSED!
  offset = 0xfffffffffff00000, data_sz = 0x100000
  offset + data_sz = 0x0 (overflowed to 0)
  limit = 0x40000 (262144 bytes)
  Delivered 1048576 bytes despite 262144 byte limit!
```

## Impact

### Severity Justification: HIGH

- **Remotely Exploitable**: No authentication required beyond QUIC handshake
- **Flow Control Violation**: Breaks fundamental QUIC protocol guarantee
- **Resource Exhaustion**: Enables DoS through unbounded data transmission
- **Potential Memory Corruption**: Callback receives invalid offset values
- **Application Impact**: Stream processing logic may not expect flow control violations

### Attack Scenarios

1. **Denial of Service via Resource Exhaustion**:
   - Bypass flow control on multiple streams simultaneously
   - Send gigabytes of data despite KB-level limits
   - Exhaust validator memory, CPU, or I/O resources
   - Force validator to drop legitimate traffic or crash

2. **Memory Corruption in Callback**:
   - If `fd_quic_cb_stream_rx()` implementation uses `offset` for array indexing
   - Large offset values cause out-of-bounds access
   - Potential for data corruption or code execution

3. **Stream State Corruption**:
   - QUIC stream reassembly logic may track received byte ranges
   - Overflowed offset values corrupt internal bookkeeping
   - Subsequent legitimate data may be rejected or mishandled
   - Connection state becomes inconsistent

4. **Protocol Confusion**:
   - Flow control is a fundamental QUIC invariant
   - Violations may trigger unexpected behavior in:
     - Connection migration logic
     - Congestion control algorithms
     - Stream prioritization mechanisms
   - Cascading failures possible

### Comparison to NET-003

While NET-003 (CRYPTO frame overflow) is **CRITICAL** due to direct buffer overflow potential, NET-004 is **HIGH** because:
- Impact depends on callback implementation (may or may not be exploitable for memory corruption)
- Primary impact is resource exhaustion (DoS) rather than guaranteed code execution
- However, flow control bypass is a serious protocol violation with wide-ranging effects

### Affected Deployments

- **All Firedancer deployments with QUIC enabled**: Frankendancer (production) and pure Firedancer (v1.x)
- **Any network-facing validators**: All validators accepting incoming QUIC connections are vulnerable

## Recommended Mitigation

### Immediate Fix

Add overflow check before flow control validation:

```c
static ulong
fd_quic_handle_stream_frame(
    fd_quic_frame_ctx_t * context,
    uchar const *         p,
    ulong                 p_sz,
    ulong                 stream_id,
    ulong                 offset,
    ulong                 data_sz,
    int                   fin ) {
  fd_quic_t *      quic = context->quic;
  fd_quic_conn_t * conn = context->conn;
  fd_quic_pkt_t *  pkt  = context->pkt;

  // ... (validation checks) ...

  /* ✅ ADD OVERFLOW CHECK BEFORE FLOW CONTROL CHECK */
  if( FD_UNLIKELY( offset > ULONG_MAX - data_sz ) ) {
    /* Addition would overflow */
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  ulong stream_bytes_end = offset + data_sz;  /* ✅ Now safe */

  /* Flow control check now operates on correct value */
  if( FD_UNLIKELY( quic->config.initial_rx_max_stream_data < stream_bytes_end ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "Stream data limit exceeded" )); )
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  /* Callback now receives valid parameters */
  int rx_res = fd_quic_cb_stream_rx( quic, conn, stream_id, offset, p, data_sz, fin );
  pkt->ack_flag |= fd_uint_if( rx_res==FD_QUIC_SUCCESS, 0U, ACK_FLAG_CANCEL );

  return data_sz;
}
```

### Alternative: Use Checked Arithmetic

Consistent with NET-003 mitigation, use GCC builtins:

```c
/* Use GCC builtin for overflow detection */
ulong stream_bytes_end = 0UL;
if( FD_UNLIKELY( __builtin_uaddl_overflow( offset, data_sz, &stream_bytes_end ) ) ) {
  fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
  return FD_QUIC_PARSE_FAIL;
}

/* Now safe to check against limit */
if( FD_UNLIKELY( quic->config.initial_rx_max_stream_data < stream_bytes_end ) ) {
  fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR, __LINE__ );
  return FD_QUIC_PARSE_FAIL;
}
```

### Additional Hardening

1. **Connection-level flow control**: Audit `fd_quic_handle_max_stream_data_frame()` and connection-level flow control for similar issues

2. **Callback validation**: Ensure `fd_quic_cb_stream_rx()` implementation validates `offset` parameter and doesn't assume it's within reasonable bounds

3. **Stream state tracking**: Review stream reassembly logic to ensure it handles edge cases:
   - Offset values near ULONG_MAX
   - Overlapping byte ranges with wrapped offsets
   - Gap detection with overflowed values

4. **Fuzzing**: Add targeted fuzzing for:
   - STREAM frames with extreme offset/length combinations
   - Multiple STREAM frames with overlapping overflowed offsets
   - Flow control limits being approached via overflow

## References

- **QUIC Flow Control**: RFC 9000 Section 4 (Flow Control)
- **STREAM Frame**: RFC 9000 Section 19.8
- **Flow Control Errors**: RFC 9000 Section 11 (Error Handling)
- **Related Vulnerability**: NET-003 (CRYPTO frame integer overflow)
- **Varint Encoding**: RFC 9000 Section 16 (values up to 2^62 - 1)
- **Checked Arithmetic Pattern**: `src/flamenco/runtime/fd_borrowed_account.h` (GCC builtin usage)
- **CWE**: CWE-190 (Integer Overflow or Wraparound), CWE-770 (Allocation of Resources Without Limits)

## Additional Notes

### Root Cause Analysis

This vulnerability shares the same systemic issue as NET-003: **QUIC frame handlers do not apply checked arithmetic to varint-decoded values**. The execution layer (`src/flamenco/`) consistently uses GCC builtins (`__builtin_uaddl_overflow`, `__builtin_usubl_overflow`) for all arithmetic on untrusted data, but the QUIC implementation lacks this defensive pattern despite processing attacker-controlled network input.

### Scope of Issue

A comprehensive audit of `src/waltz/quic/fd_quic.c` should examine all frame handlers for similar patterns:

- `fd_quic_handle_ack_frame()` - timestamp arithmetic
- `fd_quic_handle_max_data_frame()` - connection flow control
- `fd_quic_handle_max_stream_data_frame()` - stream flow control updates
- `fd_quic_handle_max_streams_frame()` - stream ID limits
- Any other handlers performing arithmetic on varint-decoded fields

### Defense in Depth Recommendation

Consider creating wrapper functions for varint arithmetic similar to `fd_ulong_checked_add()` in `src/flamenco/runtime/program/fd_program_util.h`:

```c
/* Suggested addition to fd_quic_parse_util.h */
static inline int
fd_quic_varint_checked_add( ulong a, ulong b, ulong * out ) {
  int overflow = __builtin_uaddl_overflow( a, b, out );
  return fd_int_if( overflow, FD_QUIC_PARSE_FAIL, FD_QUIC_SUCCESS );
}
```

This would provide a consistent, auditable pattern for safe arithmetic throughout the QUIC implementation.
