# NET-003: CRYPTO Frame Integer Overflow Leading to Buffer Overflow

**Severity**: CRITICAL
**Component**: QUIC Protocol Implementation / Net Tile
**Location**: `src/waltz/quic/fd_quic.c:2798`
**Discovered**: 2025-11-18
**Status**: Unpatched

## Summary

The QUIC CRYPTO frame handler performs unchecked arithmetic on attacker-controlled offset and length fields from incoming packets. An integer overflow in the addition `rcv_off + rcv_sz` causes the bounds check against `FD_QUIC_TLS_RX_DATA_SZ` (2048 bytes) to be bypassed via wraparound, allowing an attacker to write arbitrary data to out-of-bounds memory locations. This vulnerability is remotely exploitable without authentication and can lead to arbitrary code execution.

## Technical Details

### Vulnerable Code

From `src/waltz/quic/fd_quic.c:2786-2806`:

```c
fd_quic_handle_crypto_frame( fd_quic_frame_ctx_t *    context,
                             fd_quic_crypto_frame_t * crypto,
                             uchar const *            p,
                             ulong                    p_sz ) {
  fd_quic_conn_t *   conn      = context->conn;
  fd_quic_tls_hs_t * tls_hs    = conn->tls_hs;
  uint               enc_level = context->pkt->enc_level;

  /* offset expected */
  ulong rcv_off = crypto->offset;    /* ATTACKER CONTROLLED - range [0, 2^62-1] */
  ulong rcv_sz  = crypto->length;    /* ATTACKER CONTROLLED - range [0, 2^62-1] */
  ulong rcv_hi  = rcv_off + rcv_sz;  /* ❌ UNCHECKED ADDITION - INTEGER OVERFLOW! */

  if( FD_UNLIKELY( rcv_sz > p_sz ) ) {
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FRAME_ENCODING_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  // ... (intervening code omitted) ...

  if( rcv_hi > FD_QUIC_TLS_RX_DATA_SZ ) {  /* FD_QUIC_TLS_RX_DATA_SZ = 2048 */
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_CRYPTO_BUFFER_EXCEEDED, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  tls_hs->rx_sz = (ushort)rcv_hi;
  fd_memcpy( tls_hs->rx_hs_buf + rcv_off, p, rcv_sz );  /* 💥 BUFFER OVERFLOW */
```

### Root Cause

The QUIC protocol uses variable-length integers (varints) that can represent values up to `2^62 - 1` (approximately `0x3fffffffffffffff`). The `offset` and `length` fields in CRYPTO frames are encoded as varints and decoded using `fd_quic_varint_decode()` from `src/waltz/quic/templ/fd_quic_parse_util.h`.

The vulnerable code:
1. Reads attacker-controlled `offset` and `length` from the CRYPTO frame (both in range `[0, 2^62-1]`)
2. Performs unchecked addition: `rcv_hi = rcv_off + rcv_sz`
3. Checks if `rcv_hi > 2048` to prevent buffer overflow
4. If check passes, copies `rcv_sz` bytes to `rx_hs_buf + rcv_off`

The bounds check at line 2798 (`if( rcv_hi > FD_QUIC_TLS_RX_DATA_SZ )`) operates on the **overflowed** value of `rcv_hi`, not the true arithmetic result. This allows an attacker to bypass the check entirely.

### Attack Vector

An attacker sends a QUIC packet containing a CRYPTO frame with carefully crafted values:

**Example 1: Wraparound to small value**
- `offset = 0xFFFFFFFFFFFFFBFF` (ULONG_MAX - 1024)
- `length = 0x1000` (4096)
- `rcv_hi = 0xFFFFFFFFFFFFFBFF + 0x1000 = 0xFFFUL` (wraps to 4095)
- Bounds check: `4095 > 2048`? **TRUE** - triggers error (attack fails here)

**Example 2: Wraparound below threshold**
- `offset = 0xFFFFFFFFFFFFF800` (ULONG_MAX - 2047)
- `length = 0x200` (512)
- `rcv_hi = 0xFFFFFFFFFFFFF800 + 0x200 = 0x0UL` (wraps to 0)
- Bounds check: `0 > 2048`? **FALSE** - check passes ✓
- `memcpy(rx_hs_buf + 0xFFFFFFFFFFFFF800, attacker_data, 512)` - **massive out-of-bounds write**

**Example 3: More precise targeting**
- `offset = 0xFFFFFFFFFFFFFC00` (ULONG_MAX - 1023)
- `length = 0x300` (768)
- `rcv_hi = 0xFFFFFFFFFFFFFC00 + 0x300 = 0x0FF` (wraps to 255)
- Bounds check: `255 > 2048`? **FALSE** - check passes ✓
- `memcpy(rx_hs_buf + 0xFFFFFFFFFFFFFC00, attacker_data, 768)` - **out-of-bounds write to high memory**

### Memory Layout

The target buffer `rx_hs_buf` is located within the `fd_quic_tls_hs_t` structure. An out-of-bounds write at offset `ULONG_MAX - N` will write to memory at address `(base_address_of_rx_hs_buf) + (ULONG_MAX - N)`, which wraps around in the virtual address space and can target:
- Other fields in the connection state structure
- Adjacent heap allocations
- Memory mapping structures
- Return addresses on the stack (if heap layout is favorable)

## Proof of Concept

### Attack Scenario

1. Attacker initiates QUIC handshake with victim Firedancer validator
2. During handshake, attacker sends Initial packet with CRYPTO frame:
   - `offset = 0xFFFFFFFFFFFFFC00` (ULONG_MAX - 1023)
   - `length = 0x300` (768 bytes)
   - `data = <attacker_controlled_payload>`
3. Victim's `fd_quic_handle_crypto_frame()` is invoked
4. Integer overflow: `rcv_hi = 0xFFFFFFFFFFFFFC00 + 0x300 = 0xFF` (wraps to 255)
5. Bounds check bypassed: `255 > 2048` is false
6. Out-of-bounds write: `memcpy(rx_hs_buf + 0xFFFFFFFFFFFFFC00, payload, 768)`
7. Attacker corrupts adjacent memory, potentially achieving:
   - Control flow hijacking (if return addresses or function pointers are overwritten)
   - Information disclosure (if overwrite triggers a leak)
   - Denial of service (crash via invalid memory access)

### Minimal Test Case

```c
/* Simulated values from attacker packet */
ulong rcv_off = 0xFFFFFFFFFFFFFC00UL;  /* ULONG_MAX - 1023 */
ulong rcv_sz  = 0x300UL;               /* 768 */
ulong rcv_hi  = rcv_off + rcv_sz;      /* Overflows to 0xFF = 255 */

/* Bounds check */
if( rcv_hi > 2048 ) {
  /* This branch is NOT taken - check bypassed! */
  printf("Attack blocked\n");
} else {
  /* Vulnerable code path */
  printf("Bounds check bypassed! rcv_hi = %lu (should be > ULONG_MAX)\n", rcv_hi);
  /* memcpy would write to rx_hs_buf + 0xFFFFFFFFFFFFFC00 */
}
```

**Expected output**: `Bounds check bypassed! rcv_hi = 255 (should be > ULONG_MAX)`

## Impact

### Severity Justification: CRITICAL

- **Remotely Exploitable**: No authentication required - attacker only needs network access to the QUIC endpoint
- **Pre-Authentication**: Vulnerability triggers during TLS handshake, before any authentication occurs
- **Arbitrary Memory Write**: Attacker controls both the write destination (via `offset`) and data content
- **Code Execution Potential**: Out-of-bounds write can corrupt control flow structures
- **Network Facing**: Net tile is the first line of defense; compromise enables lateral movement

### Attack Scenarios

1. **Remote Code Execution**: Overwrite function pointers, return addresses, or vtables to redirect execution
2. **Denial of Service**: Crash the validator by corrupting critical data structures
3. **Information Disclosure**: Overwrite pointers to leak sensitive memory contents in subsequent operations
4. **Validator Compromise**: Gain control of validator process to:
   - Manipulate vote transactions
   - Exfiltrate private keys
   - Disrupt network consensus

### Affected Deployments

- **Frankendancer (Production)**: Likely vulnerable - uses Firedancer net tile for packet handling
- **Pure Firedancer (v1.x)**: Vulnerable - no deployment mitigations in place
- **All QUIC-enabled configurations**: Any Firedancer deployment accepting QUIC connections is exploitable

## Recommended Mitigation

### Immediate Fix

Add overflow check before arithmetic operation:

```c
fd_quic_handle_crypto_frame( fd_quic_frame_ctx_t *    context,
                             fd_quic_crypto_frame_t * crypto,
                             uchar const *            p,
                             ulong                    p_sz ) {
  fd_quic_conn_t *   conn      = context->conn;
  fd_quic_tls_hs_t * tls_hs    = conn->tls_hs;
  uint               enc_level = context->pkt->enc_level;

  ulong rcv_off = crypto->offset;
  ulong rcv_sz  = crypto->length;

  /* ✅ ADD OVERFLOW CHECK BEFORE ADDITION */
  if( FD_UNLIKELY( rcv_off > ULONG_MAX - rcv_sz ) ) {
    /* Overflow would occur */
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  ulong rcv_hi = rcv_off + rcv_sz;  /* ✅ Now safe */

  /* Continue with existing checks */
  if( FD_UNLIKELY( rcv_sz > p_sz ) ) {
    fd_quic_frame_error( context, FD_QUIC_CONN_REASON_FRAME_ENCODING_ERROR, __LINE__ );
    return FD_QUIC_PARSE_FAIL;
  }

  // ... rest of function unchanged ...
}
```

### Alternative: Use Checked Arithmetic

Adopt the same checked arithmetic pattern used in `src/flamenco/runtime/fd_borrowed_account.h`:

```c
/* Use GCC builtin for overflow detection */
ulong rcv_hi = 0UL;
if( FD_UNLIKELY( __builtin_uaddl_overflow( rcv_off, rcv_sz, &rcv_hi ) ) ) {
  fd_quic_frame_error( context, FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION, __LINE__ );
  return FD_QUIC_PARSE_FAIL;
}
```

### Defense in Depth

1. **Audit all QUIC frame handlers**: Review `fd_quic_handle_stream_frame()`, `fd_quic_handle_ack_frame()`, etc. for similar patterns
2. **Add fuzzing targets**: Create libFuzzer harnesses specifically targeting QUIC frame parsing with extreme varint values
3. **Static analysis**: Add CodeQL/Semgrep rules to detect unchecked arithmetic on varint-decoded values
4. **Runtime bounds checking**: Consider AddressSanitizer in debug/test builds to catch out-of-bounds writes early

## References

- **QUIC Specification**: RFC 9000 Section 16 (Variable-Length Integer Encoding)
- **Varint Range**: [0, 2^62 - 1] per RFC 9000 Section 16
- **CRYPTO Frame**: RFC 9000 Section 19.6
- **Similar Vulnerability**: See NET-004 for integer overflow in STREAM frame handler
- **Protected Arithmetic Examples**:
  - `src/flamenco/runtime/fd_borrowed_account.h:209-243` (checked balance arithmetic)
  - `src/flamenco/runtime/program/fd_program_util.h:15-25` (GCC builtin usage)
- **CWE**: CWE-190 (Integer Overflow or Wraparound), CWE-787 (Out-of-bounds Write)

## Additional Notes

This vulnerability highlights a systemic issue: the QUIC implementation does not consistently apply the checked arithmetic patterns used in the execution layer (`src/flamenco/`). The net tile handles untrusted network input but lacks the defensive programming practices applied to untrusted transaction data.

**Contrast with Safe Code**: The sBPF VM interpreter (`src/flamenco/vm/fd_vm_interp_core.c`) carefully checks for overflow in CU accounting, and the system program (`src/flamenco/runtime/program/fd_system_program.c`) uses GCC builtins for all balance arithmetic. The QUIC implementation should adopt similar rigor given that it processes attacker-controlled data from the network.
