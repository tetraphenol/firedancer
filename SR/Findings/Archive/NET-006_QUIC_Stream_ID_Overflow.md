# NET-006: QUIC Stream ID Calculation Integer Overflow

**Category**: Network / QUIC
**Severity**: MEDIUM
**Component**: QUIC Transport (`fd_quic.c`)
**Status**: Confirmed

## Summary

The QUIC stream ID supremum calculation uses `(initial_max_streams_uni << 2) + stream_type` without overflow protection. A malicious peer sending `initial_max_streams_uni` with high bits set causes the left-shift to overflow, wrapping the stream limit to a near-zero value. This renders the connection unusable for stream creation.

## Technical Details

Three vulnerable code paths exist:

### Path 1: Transport Parameter Processing (line 4266)
```c
srx->rx_sup_stream_id = (state->transport_params.initial_max_streams_uni<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;
```

### Path 2: Peer Transport Parameter Processing (lines 2706-2708)
```c
conn->tx_sup_stream_id = ( (ulong)peer_tp->initial_max_streams_uni << 2UL ) + FD_QUIC_STREAM_TYPE_UNI_SERVER;
```

### Path 3: MAX_STREAMS Frame Processing (line 5127)
```c
ulong peer_sup_stream_id = data->max_streams * 4UL + type;
conn->tx_sup_stream_id = fd_ulong_max( peer_sup_stream_id, conn->tx_sup_stream_id );
```

No bounds validation exists on `initial_max_streams_uni` or `max_streams` before the arithmetic.

### Overflow Example
```
initial_max_streams_uni = 0xC000000000000000
<< 2 = 0x0000000000000000  (overflow)
+ 2  = 0x0000000000000002  (stream type)

Result: rx_sup_stream_id = 2
Stream check: stream_id >= 2 → almost all streams rejected
```

## Impact

- Connection-level DoS: stream creation blocked after handshake
- Per-connection impact (not global), but requires reconnection to recover
- Attacker can cause repeated connection failures

## Proof of Concept

Malicious QUIC client sets `initial_max_streams_uni = 0xC000000000000000` in transport parameters during TLS handshake.

## Remediation

Validate `initial_max_streams_uni` against `(1UL<<62)-1` (RFC 9000 max) before the shift:
```c
if( initial_max_streams_uni > (1UL<<62)-1 ) {
  /* protocol violation */
  return;
}
```

## References

- `src/waltz/quic/fd_quic.c:4266` (transport params)
- `src/waltz/quic/fd_quic.c:2706-2708` (peer params)
- `src/waltz/quic/fd_quic.c:5127` (MAX_STREAMS frame)
- RFC 9000 Section 4.6: Stream limits
