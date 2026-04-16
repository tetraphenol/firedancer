# MEDIUM-HIGH: QUIC PATH_CHALLENGE/PATH_RESPONSE Not Implemented

**Category**: NET
**Severity**: Medium-High
**Component**: QUIC (Waltz)
**Location**: `src/waltz/quic/fd_quic.c:5203-5224`

## Summary

The QUIC implementation silently ignores both PATH_CHALLENGE and PATH_RESPONSE frames, with an explicit FIXME comment. Per RFC 9000 Section 9.3, PATH_CHALLENGE is used to validate peer reachability during connection migration. Without this, there is no path validation mechanism to verify that a peer actually controls the claimed source address during migration.

## Technical Details

```c
// fd_quic.c:5203-5212
static ulong
fd_quic_handle_path_challenge_frame( ... ) {
  /* FIXME The recipient of this frame MUST generate a PATH_RESPONSE frame
     (Section 19.18) containing the same Data value. */
  FD_DTRACE_PROBE_1( quic_handle_path_challenge_frame, context->conn->our_conn_id );
  (void)data;
  return 0UL;  // silently ignored
}

// fd_quic.c:5215-5224
static ulong
fd_quic_handle_path_response_frame( ... ) {
  /* We don't generate PATH_CHALLENGE frames, so this frame should never arrive */
  (void)data;
  return 0UL;  // silently ignored
}
```

Both handlers discard the frame data entirely and return success (0).

## Impact

- No path validation during QUIC connection migration
- A peer claiming connection migration cannot be verified to control the new address
- If connection migration is triggered (e.g., NAT rebinding), the peer's new address is accepted without validation
- Potential for connection state confusion if multiple peers claim the same connection ID from different addresses
- RFC 9000 compliance gap (Section 9.3: "An endpoint MUST validate that the peer is reachable at the new address before confirming the migration")

**Mitigating factors**: Firedancer's QUIC is server-only for TPU, and connection migration may be rare in practice. However, the FIXME indicates the developers recognize this needs implementation.

## Remediation

Implement PATH_CHALLENGE handler: store the 8-byte challenge data and respond with PATH_RESPONSE containing the same data. Implement PATH_RESPONSE handler for validating outgoing challenges.

## References

- `src/waltz/quic/fd_quic.c:5203-5224`
- RFC 9000 Section 9.3 (Responding to Connection Migration)
- RFC 9000 Section 19.17/19.18 (PATH_CHALLENGE/PATH_RESPONSE frames)
