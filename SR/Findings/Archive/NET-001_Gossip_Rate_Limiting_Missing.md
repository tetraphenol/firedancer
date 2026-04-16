# NET-001: Missing Gossip Protocol Rate Limiting

## Severity
**CRITICAL / HIGH**

## Summary
The gossip protocol implementation lacks any rate limiting or traffic shaping on incoming messages, allowing malicious peers to flood validators with unlimited gossip traffic, causing CPU exhaustion, memory pressure, and network bandwidth saturation.

## Affected Components
- `src/flamenco/gossip/fd_gossip.c:679-713` (main message receive handler)
- `src/flamenco/gossip/fd_gossip.c:685` (explicit TODO acknowledgment)
- All gossip message handlers:
  - `rx_pull_request()` - Pull request handler
  - `rx_pull_response()` - Pull response handler
  - `rx_push_message()` - Push message handler
  - `rx_prune_message()` - Prune message handler
  - `rx_ping()` / `rx_pong()` - Ping/pong handlers

## Technical Details

### Vulnerability Mechanism

The code explicitly acknowledges this vulnerability in `src/flamenco/gossip/fd_gossip.c:685`:

```c
fd_gossip_rx( fd_gossip_t *       gossip,
              fd_ip4_port_t       peer,
              uchar const *       data,
              ulong               data_sz,
              long                now,
              fd_stem_context_t * stem ) {
  /* TODO: Implement traffic shaper / bandwidth limiter */
  FD_TEST( data_sz>=sizeof(fd_gossip_view_t) );
  fd_gossip_view_t const * view    = (fd_gossip_view_t const *)data;
  uchar const *            payload = data+sizeof(fd_gossip_view_t);

  switch( view->tag ) {
    case FD_GOSSIP_MESSAGE_PULL_REQUEST:
      rx_pull_request( gossip, view->pull_request, payload, peer, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PULL_RESPONSE:
      rx_pull_response( gossip, view->pull_response, payload, stem, now );
      break;
    case FD_GOSSIP_MESSAGE_PUSH_MESSAGE:
      rx_push_message( gossip, view->push_message, payload, stem, now );
      break;
    // ... other message types processed without rate limiting
  }
}
```

**Current Protections:**
- Signature verification via Ed25519 (in separate `fd_gossvf_tile.c` verification tile)
- CRDS (Cluster Replicated Data Store) size limited to 32,768 entries with LRU eviction
- Duplicate message filtering via CRDS lookup

**The Gap:**
While signatures are validated and CRDS size is bounded, there is **no limit on the rate at which messages are processed** from any individual peer or globally:

```
Malicious Peer Can Send:
- 1,000+ gossip messages per second
- Each message triggers signature verification (CPU intensive)
- Each message triggers CRDS lookups and potential updates
- No backpressure or throttling applied
```

### Code Evidence

From `src/flamenco/gossip/fd_gossip.c:685`:
```c
/* TODO: Implement traffic shaper / bandwidth limiter */
```

This TODO explicitly acknowledges the missing rate limiting functionality.

### Attack Scenario

**Objective**: Exhaust validator CPU and network resources via gossip flood.

**Attack Vector 1: Gossip Message Flood**
1. Attacker joins gossip network as malicious peer
2. Sends maximum-rate gossip messages to target validator:
   - Pull requests with varying bloom filters
   - Push messages with (possibly duplicate) CRDS entries
   - Ping messages requiring pong responses
3. Target validator processes all messages:
   - Ed25519 signature verification for each (CPU intensive)
   - CRDS lookups and updates (memory/CPU)
   - Network bandwidth consumed
4. Validator performance degrades:
   - High CPU usage in gossip/verification tiles
   - Reduced capacity for transaction processing
   - Potential block production delays

**Attack Vector 2: Amplification via Pull Responses**
1. Attacker sends pull requests with wide-open bloom filters
2. Victim responds with large pull responses (up to CRDS limit)
3. Attacker repeats with minimal CPU cost
4. Victim expends significant CPU generating responses

**Attack Vector 3: Distributed Gossip DoS**
1. Attacker controls multiple gossip peers
2. Each peer sends high-rate gossip traffic
3. Aggregate traffic overwhelms validator
4. No per-peer rate limiting to throttle attack

**Prerequisites**:
- Ability to send UDP packets to gossip port (8001 by default)
- Knowledge of validator's gossip endpoint (publicly advertised)
- No stake or authentication required

### Impact Assessment

**Availability Impact**: HIGH
- Validator CPU exhaustion on gossip/verification tiles
- Network bandwidth saturation
- Degraded transaction processing performance
- Potential block production delays/failures
- Service degradation without full crash

**Resource Consumption**:
- CPU: Signature verification is ~50k-100k cycles per message
- Memory: CRDS bounded at 32,768 entries but churning/eviction increases
- Network: Bandwidth consumed by flood and response traffic
- I/O: Increased logging and monitoring overhead

**Scope**:
- Affects all validators with public gossip endpoints
- No stake or special privileges required
- Attack can be sustained indefinitely
- Multiple attackers can amplify impact

**Comparison to Agave**:
Need to verify if Agave/Solana Labs client implements rate limiting that Firedancer lacks.

## Proof of Concept

```python
#!/usr/bin/env python3
"""
Gossip flood PoC - demonstrates lack of rate limiting
WARNING: For authorized testing only
"""

import socket
import time
from construct import *

# Simplified gossip message structure
GossipMessage = Struct(
    "tag" / Int32ul,  # Message type
    "payload" / Bytes(1024)  # Dummy payload
)

def gossip_flood(target_ip, target_port, rate_limit=None):
    """
    Send high-rate gossip messages to target

    Args:
        target_ip: Victim validator gossip IP
        target_port: Victim gossip port (default 8001)
        rate_limit: Optional messages per second (None = unlimited)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    count = 0
    start = time.time()

    while True:
        # Construct gossip message (would need proper serialization)
        # This is simplified - real attack needs valid signatures
        msg = GossipMessage.build({
            "tag": 0,  # PULL_REQUEST
            "payload": b'\x00' * 1024
        })

        sock.sendto(msg, (target_ip, target_port))
        count += 1

        if rate_limit:
            time.sleep(1.0 / rate_limit)

        if count % 1000 == 0:
            elapsed = time.time() - start
            print(f"Sent {count} messages in {elapsed:.1f}s ({count/elapsed:.0f} msg/s)")

# Example usage (DO NOT RUN against production systems):
# gossip_flood("192.168.1.100", 8001, rate_limit=1000)
```

**Note**: This PoC is simplified. Real attack requires:
- Proper Solana gossip message serialization
- Valid Ed25519 signatures (attacker uses their own keypair)
- Bloom filter construction for pull requests
- CRDS entry construction for push messages

However, the lack of rate limiting means even with valid messages, unlimited traffic is accepted.

## Exploitation Difficulty
**LOW to MEDIUM**

**Factors Decreasing Difficulty:**
- No authentication required (just valid signatures with any keypair)
- Gossip endpoints publicly advertised
- Standard UDP packet sending
- Attack can use legitimate message types
- No stake required

**Factors Increasing Difficulty:**
- Attacker must craft valid Solana gossip messages
- Signature verification still required (attacker uses own key)
- CRDS deduplication reduces some impact
- May require distributed attack for significant impact

## Recommended Mitigations

### 1. Implement Per-Peer Token Bucket Rate Limiter (Immediate Fix)

Add rate limiting to `src/flamenco/gossip/fd_gossip.c`:

```c
#define FD_GOSSIP_RATE_LIMIT_BURST    100UL  // 100 message burst
#define FD_GOSSIP_RATE_LIMIT_SUSTAIN  50UL   // 50 messages/sec sustained
#define FD_GOSSIP_RATE_LIMIT_WINDOW   1000000000UL  // 1 second in nanoseconds

typedef struct {
  fd_ip4_port_t peer;
  ulong         tokens;        // Current token count
  long          last_refill;   // Last refill timestamp (ns)
} fd_gossip_peer_rate_limit_t;

static int
fd_gossip_rate_limit_check( fd_gossip_t * gossip,
                            fd_ip4_port_t peer,
                            long          now ) {
  // Find or create rate limit entry for peer
  fd_gossip_peer_rate_limit_t * limit = find_or_create_limit(gossip, peer);

  // Refill tokens based on elapsed time
  long elapsed = now - limit->last_refill;
  if( elapsed > 0 ) {
    ulong new_tokens = (elapsed * FD_GOSSIP_RATE_LIMIT_SUSTAIN) / FD_GOSSIP_RATE_LIMIT_WINDOW;
    limit->tokens = fd_ulong_min(limit->tokens + new_tokens, FD_GOSSIP_RATE_LIMIT_BURST);
    limit->last_refill = now;
  }

  // Check if tokens available
  if( limit->tokens > 0 ) {
    limit->tokens--;
    return 1;  // Allow
  }

  FD_MCNT_INC(GOSSIP, RATE_LIMITED, 1UL);
  return 0;  // Reject
}

// In fd_gossip_rx():
void
fd_gossip_rx( fd_gossip_t *       gossip,
              fd_ip4_port_t       peer,
              uchar const *       data,
              ulong               data_sz,
              long                now,
              fd_stem_context_t * stem ) {
  // Rate limit check BEFORE signature verification
  if( !fd_gossip_rate_limit_check(gossip, peer, now) ) {
    FD_LOG_WARNING(("Gossip rate limit exceeded for peer %08x:%u", peer.ip, peer.port));
    return;  // Drop message
  }

  // ... existing message processing ...
}
```

### 2. Implement Global Rate Limiting

Add aggregate rate limiting across all peers:

```c
#define FD_GOSSIP_GLOBAL_RATE_LIMIT  5000UL  // 5000 msg/sec globally

static ulong gossip_global_msg_count = 0;
static long  gossip_global_msg_window_start = 0;

static int
fd_gossip_global_rate_limit_check( long now ) {
  // Reset counter every second
  if( now - gossip_global_msg_window_start > FD_GOSSIP_RATE_LIMIT_WINDOW ) {
    gossip_global_msg_count = 0;
    gossip_global_msg_window_start = now;
  }

  if( gossip_global_msg_count < FD_GOSSIP_GLOBAL_RATE_LIMIT ) {
    gossip_global_msg_count++;
    return 1;
  }

  return 0;  // Global limit exceeded
}
```

### 3. Implement Stake-Weighted Rate Limiting

Allocate higher rate limits to staked validators:

```c
static ulong
fd_gossip_compute_rate_limit( fd_gossip_t * gossip, fd_pubkey_t const * peer_pubkey ) {
  ulong stake = lookup_peer_stake(gossip, peer_pubkey);

  if( stake == 0 ) {
    return 10UL;  // Unstaked: 10 msg/sec
  } else if( stake < 1000000UL ) {
    return 50UL;  // Low stake: 50 msg/sec
  } else {
    return 200UL;  // High stake: 200 msg/sec
  }
}
```

### 4. Add Backpressure Mechanism

When under load, signal to peers to reduce message rate:
- Send PRUNE messages more aggressively
- Reduce pull response sizes
- Add explicit backpressure signaling in protocol (requires protocol change)

### 5. Monitoring and Adaptive Rate Limiting

Monitor CPU usage and adjust rate limits dynamically:

```c
// If gossip tile CPU > 80%, reduce rate limits by 50%
if( fd_tile_cpu_usage() > 0.8 ) {
  global_rate_limit_multiplier = 0.5;
}
```

## Detection Strategies

### Runtime Monitoring

Monitor these metrics for gossip flood attacks:
- `gossip_messages_per_second > 1000` from single peer
- `gossip_cpu_usage > 80%` sustained
- `gossip_bandwidth > expected_baseline * 10`
- Sudden increase in signature verification failures

### Alerting Thresholds
```
ALERT: gossip_msg_rate_per_peer > 100/sec
ALERT: gossip_global_msg_rate > 5000/sec
ALERT: gossip_tile_cpu > 80% for 60 seconds
ALERT: gossip_bandwidth_in > 100 Mbps
```

### Logging

Add to gossip receive handler:
```c
FD_LOG_INFO(("Gossip rx: peer=%08x:%u type=%u size=%lu",
             peer.ip, peer.port, view->tag, data_sz));

// Log rate limit violations
FD_LOG_WARNING(("Gossip rate limit exceeded: peer=%08x:%u count=%lu",
                peer.ip, peer.port, peer_msg_count));
```

### Metrics to Track
- `fd_gossip_msg_rx_count` - Total messages received
- `fd_gossip_msg_rx_bytes` - Total bytes received
- `fd_gossip_msg_rate_limited` - Messages dropped due to rate limiting
- `fd_gossip_msg_per_peer_histogram` - Distribution of messages per peer

## References

### Similar Vulnerabilities
- **CVE-2018-17145** (Bitcoin) - Uncontrolled resource consumption in P2P network
- **Ethereum P2P DoS** - Various DoS vectors in gossip/devp2p protocols
- **OWASP**: Unvalidated input / Resource exhaustion

### Solana Protocol Discussion
- Check if Agave/Solana Labs implementation has rate limiting
- Verify if rate limiting is protocol-specified or implementation-specific
- Consider proposing SIMD for standard rate limiting parameters

### Internal References
- `src/flamenco/gossip/fd_gossip.c:685` - TODO comment acknowledging gap
- `src/discof/gossip/fd_gossvf_tile.c` - Signature verification tile
- `src/flamenco/gossip/crds/fd_crds.c` - CRDS data structure (has size limits)
- `SR/Checklist.md` - Section 6.2 (Gossip Protocol Security)

## Timeline
- **Discovered**: 2025-11-18 (Phase 6 security assessment)
- **Reported**: 2025-11-18
- **Status**: UNFIXED (acknowledged in TODO comment but not implemented)

## Additional Notes

This vulnerability is explicitly acknowledged by the Firedancer team via the TODO comment at line 685, indicating awareness of the missing functionality.

**Key Observations:**
1. Signature verification provides some defense (invalid signatures rejected)
2. CRDS size limits prevent unbounded memory growth
3. However, CPU exhaustion from processing unlimited valid messages is still possible
4. Rate limiting is defense-in-depth and standard practice for P2P protocols

**Architectural Considerations:**
- Rate limiting should occur BEFORE signature verification (save CPU)
- Consider integrating with Firedancer's tile/flow control architecture
- May need coordination with networking layer (quic/udp tiles)

**Testing Recommendations:**
- Benchmark gossip throughput with and without rate limiting
- Test behavior under sustained high-rate legitimate traffic
- Verify rate limits don't impact normal gossip propagation
- Test stake-weighted rate limiting with various stake distributions

**Comparison with Other Clients:**
- Research Agave/Solana Labs rate limiting implementation
- Check Jito-Solana for any enhanced rate limiting
- Consider industry best practices (Bitcoin, Ethereum, Cosmos gossip protocols)
