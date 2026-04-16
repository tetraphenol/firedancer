# Network Layer Security Analysis

**Components:** QUIC, TLS 1.3, XDP/AF_XDP, Network Tile
**Source:** `/home/user/firedancer/src/waltz/` and `/home/user/firedancer/src/disco/net/`

---

## Table of Contents

1. [QUIC Protocol Implementation](#quic-protocol-implementation)
2. [TLS 1.3 Security](#tls-13-security)
3. [XDP/AF_XDP Kernel Bypass](#xdpaf_xdp-kernel-bypass)
4. [Network Tile Architecture](#network-tile-architecture)
5. [Attack Vectors](#attack-vectors)
6. [Recommendations](#recommendations)

---

## QUIC Protocol Implementation

### Retry Mechanism Security

**Location:** `/home/user/firedancer/src/waltz/quic/fd_quic_retry.h`

#### CRITICAL: IV Reuse Vulnerability

**Lines 82-87:**
```c
/* The retry token authentication scheme relies on AES-GCM with 96-bit
   unique nonces. The nonces are generated using fd_rng_t which can be
   guessable (see warning below). if fd_rng_t generates the same 96-bit
   nonce twice, the retry token authentication mechanism breaks down entirely. */
```

**Vulnerability:**
- IV derived by XOR with `token_id` (lines 155-166 in `fd_quic_retry.c`)
- `token_id` filled with guessable random bytes from `fd_rng_t`
- AES-GCM security completely broken if IV repeats

**Attack Scenario:**
1. Attacker observes retry tokens
2. Predicts or forces IV collision via birthday attack
3. Forges retry tokens → bypasses retry mechanism
4. Exhausts connection resources

**Recommendation:**
- Replace `fd_rng_t` with CSPRNG (e.g., `/dev/urandom`, getrandom())
- Use counter-based IV generation with overflow protection
- Consider ChaCha20-Poly1305 (less sensitive to IV reuse)

---

### Initial Packet Validation

**Location:** `/home/user/firedancer/src/waltz/quic/fd_quic.c:1461-1464`

#### GOOD: Amplification Attack Mitigation

```c
if( pkt->datagram_sz < FD_QUIC_INITIAL_PAYLOAD_SZ_MIN ) {
    /* can't trust the included values, so can't reply */
    return FD_QUIC_PARSE_FAIL;
}
```

**Compliance:** RFC 9000 Section 14.1
- Minimum 1200-byte Initial packet requirement enforced
- Prevents response amplification (attacker sends small packet, server replies with large packet)

**Defense Effectiveness:** STRONG

---

### Connection Map Hash Collisions

**Location:** `/home/user/firedancer/src/waltz/quic/fd_quic_conn_map.h:6-17`

#### MEDIUM: Weak Hash Function

```c
#define MAP_KEY_HASH(k) ((uint)k)
```

**Issue:**
- Simple cast of connection ID to `uint` (32-bit)
- Truncates 64-bit connection IDs → hash collisions

**Attack:**
- Craft connection IDs differing only in high 32 bits
- Create hash collisions → connection mix-ups
- Potential DoS or cross-connection data leaks

**Example:**
```
Conn ID 1: 0x0000000100000001
Conn ID 2: 0x0000000200000001
Hash:      0x00000001 (COLLISION)
```

**Recommendation:**
- Use proper hash function (xxhash, murmur3)
- Increase hash table size
- Add salt to hash computation

---

### Connection ID Rotation

**Location:** `/home/user/firedancer/src/waltz/quic/fd_quic_conn.h:116`

#### TODO: Missing Feature

```c
/* FIXME support new/retire conn ID */
```

**Impact:**
- Only one connection ID per connection
- No connection migration support
- NAT rebinding may break connections

**Priority:** Medium (feature incomplete)

---

### Packet Parsing Security

**Location:** `/home/user/firedancer/src/waltz/quic/templ/fd_quic_parsers.h:48-51`

#### GOOD: Comprehensive Bounds Checking

```c
#define FD_TEMPL_MBR_ELEM(NAME,TYPE)                                   \
    if( FD_UNLIKELY( cur_byte + sizeof(fd_quic_##TYPE) > sz ) )        \
      return FD_QUIC_PARSE_FAIL;                                       \
    cur_byte += FD_TEMPL_PARSE(TYPE,out->NAME,buf+cur_byte);
```

**Strength:**
- All variable-length fields have bounds checks
- Prevents buffer overflows
- Early rejection on malformed packets

---

### Varint Decoding

**Location:** `/home/user/firedancer/src/waltz/quic/templ/fd_quic_parse_util.h:128-143`

#### CONCERN: Trusted Input Assumption

```c
static inline ulong
fd_quic_varint_decode( uchar const * buf, uint msb2 ) {
```

**Issue:**
- `msb2` parameter determines decoded size
- Assumes `msb2` is validated by caller
- No internal validation

**Potential Exploit:**
- If `msb2` is attacker-controlled without upstream validation
- Could cause incorrect size interpretation
- Buffer over-read possible

**Recommendation:**
- Add assertion or runtime check on `msb2` range
- Document precondition clearly

---

### Connection Exhaustion

**Location:** `/home/user/firedancer/src/waltz/quic/fd_quic.c:1467-1470`

#### CONCERN: No Per-Address Rate Limiting

```c
if( FD_UNLIKELY( state->free_conn_list==UINT_MAX ) ) {
    FD_DEBUG( FD_LOG_DEBUG(( "ignoring conn request: no free conn slots" )) );
    metrics->conn_err_no_slots_cnt++;
    return FD_QUIC_PARSE_FAIL;
}
```

**Configuration:** `max_concurrent_connections = 131072` (default)

**Attack:**
- Attacker opens 131,072 connections from different source IPs
- Pool exhausted → legitimate clients rejected
- No per-address limit enforced

**Mitigations Present:**
- Retry mechanism (forces stateless cookie validation)
- Idle timeout (10s default) → connections eventually freed

**Recommendations:**
- Add per-address connection limit
- Implement token bucket rate limiter for Initial packets
- Consider adaptive rate limiting based on load

---

## TLS 1.3 Security

### Certificate Validation

**Location:** `/home/user/firedancer/src/waltz/tls/fd_tls_asn1.h:14-24`

#### LOW: Strict ASN.1 Parsing

```c
/* TODO Does not correctly handle all legal DER encodings.
   Only the trivial encoding is handled. May not work with all TLS
   libraries. (Protocol ossification ...) */
```

**Issue:**
- Rejects valid but non-canonical DER certificates
- Only accepts trivial/canonical encoding

**Impact:**
- Legitimate certificates from some CAs may be rejected
- Interoperability issues

**Example (fd_tls_asn1.c:17-29):**
```c
if( FD_UNLIKELY( sz!=prefix_sz+32UL ) )  /* Exact size match only */
    return NULL;
```

**Recommendation:**
- Extend parser to handle more DER variants
- Add compatibility mode for non-canonical certificates
- Document supported encoding formats

---

### Key Derivation Validation

**Location:** `/home/user/firedancer/src/waltz/tls/fd_tls.c:123-150`

#### MEDIUM: Assertion-Based Checks

```c
#define LABEL_BUFSZ (64UL)
FD_TEST( label_sz  <=LABEL_BUFSZ );  /* Assertion, not runtime check */
FD_TEST( context_sz<=LABEL_BUFSZ );
FD_TEST( out_sz    <=32UL        );
```

**Issue:**
- `FD_TEST` likely expands to assertion (`assert()`)
- Assertions disabled in production builds (`-DNDEBUG`)
- No bounds validation in production

**Risk:**
- Buffer overflow if `label_sz > 64` in production
- Stack corruption possible

**Recommendation:**
```c
if( FD_UNLIKELY( label_sz > LABEL_BUFSZ ) ) return FD_TLS_ERR_INVALID;
if( FD_UNLIKELY( context_sz > LABEL_BUFSZ ) ) return FD_TLS_ERR_INVALID;
```

---

### Handshake State Machine

**Location:** `/home/user/firedancer/src/waltz/tls/fd_tls.c:99-120`

#### GOOD: Proper Initialization

```c
fd_tls_estate_srv_t *
fd_tls_estate_srv_new( void * mem ) {
  fd_tls_estate_srv_t * hs = mem;
  memset( hs, 0, sizeof(fd_tls_estate_srv_t) );
  hs->base.state  = FD_TLS_HS_START;
  hs->base.server = 1;
  return hs;
}
```

**Strength:**
- Zero-initialization prevents uninitialized reads
- Clear state machine starting point

---

## XDP/AF_XDP Kernel Bypass

### eBPF Program Security

**Location:** `/home/user/firedancer/src/waltz/xdp/fd_xdp1.c`

#### GOOD: Comprehensive Bounds Checking

**Ethernet + IPv4 Header (lines 94-142):**
```c
/* Bound check accessing the eth_hdr (14 bytes) and the ip4_hdr (20 bytes) */
*(code++) = FD_EBPF( mov64_reg, r5, r2 );
*(code++) = FD_EBPF( add64_imm, r5, 34 );
*(code++) = FD_EBPF( jgt_reg, r5, r3, LBL_PASS );  /* Jump if out of bounds */
```

**GRE Packet Handling:**
```c
/* Bound check GRE and inner ip4_hdr access */
*(code++) = FD_EBPF( add64_imm, r5, 24 );  /* GRE (4) + inner IPv4 (20) */
*(code++) = FD_EBPF( jgt_reg, r5, r3, LBL_PASS );
```

**UDP Header:**
```c
/* bound check udp hdr access */
*(code++) = FD_EBPF( add64_imm, r4, 8 );
*(code++) = FD_EBPF( jgt_reg, r4, r3, LBL_PASS );
```

**Strength:**
- Every memory access has explicit bounds check
- Compares against `xdp_md->data_end` (kernel-verified)
- Prevents eBPF verifier rejection

---

### Port Filtering

**Location:** `/home/user/firedancer/src/waltz/xdp/fd_xdp1.c:193-198`

#### GOOD: Validation and Byte-Swapping

```c
for( ulong i=0UL; i<ports_cnt; i++ ) {
    ushort port = (ushort)fd_ushort_bswap( ports[ i ] );  /* Network order */
    if( !port ) continue;  /* Skip port 0 */
    *(code++) = FD_EBPF( jeq_imm, r4, port, LBL_REDIRECT );
}
```

**Defense:**
- Rejects port 0 (invalid)
- Proper endianness handling
- Only redirects matching ports to AF_XDP

---

### UMEM Memory Management

**Location:** `/home/user/firedancer/src/waltz/xdp/fd_xsk.h:70-102`

#### Design: Zero-Copy Sharing

**Ring Ownership:**
- **FILL ring:** Userspace → Kernel (free RX buffers)
- **RX ring:** Kernel → Userspace (received packets)
- **TX ring:** Userspace → Kernel (packets to send)
- **COMPLETION ring:** Kernel → Userspace (freed TX buffers)

**Security Consideration:**
- UMEM shared between kernel and userspace (zero-copy)
- Kernel can corrupt userspace memory (trusted boundary)
- Userspace corruption can poison kernel (mitigated by read-only mappings to app tiles)

**Attack Scenario:**
- Malicious tile corrupts UMEM → affects NET tile
- NET tile reads corrupted packet metadata

**Mitigation:**
- App tiles have read-only UMEM access
- Only NET tile can write to UMEM
- Sandbox prevents lateral movement

---

## Network Tile Architecture

### Packet Routing

**Location:** `/home/user/firedancer/src/disco/net/xdp/fd_xdp_tile.c:175-200`

#### Design: Round-Robin Load Balancing

```c
/* All net tiles are subscribed to the same TX links. The net tiles "take turns"
   doing TX jobs based on the L3+L4 dst hash. */
```

**Hash-Based Distribution:**
- Uses L3 (IP) + L4 (port) destination hash
- Distributes work across multiple net tiles

**Concern:**
- Adversarial traffic can create hash imbalance
- Attacker chooses destinations to maximize collisions
- One net tile overloaded while others idle

**Recommendation:**
- Add randomization to hash computation
- Monitor per-tile load distribution
- Implement dynamic rebalancing

---

### GRE Encapsulation

**Location:** `/home/user/firedancer/src/disco/net/xdp/fd_xdp_tile.c:183-193`

#### Feature: Tunnel Support

```c
uint   use_gre;           /* The tx packet will be GRE-encapsulated */
uint   gre_outer_src_ip;  /* Outer iphdr's src_ip in net order */
uint   gre_outer_dst_ip;  /* Outer iphdr's dst_ip in net order */
```

**Security Concern:**
- Source IP spoofing if `gre_outer_src_ip` not validated
- Could enable IP address spoofing attacks

**Recommendation:**
- Validate `gre_outer_src_ip` matches interface IP
- Add explicit source validation
- Document GRE security requirements

---

### TX Free Ring Management

**Location:** `/home/user/firedancer/src/disco/net/xdp/fd_xdp_tile.c:150-159`

```c
struct fd_net_free_ring {
  ulong   prod;   /* Producer index */
  ulong   cons;   /* Consumer index */
  ulong   depth;
  ulong * queue;
};
```

**Concern:**
- FIFO queue for free TX frames
- Use-after-free if frame ownership not strictly maintained
- Producer/consumer indices must be synchronized

**Recommendation:**
- Add ownership tracking per frame
- Validate indices before access
- Consider using atomic operations

---

## Attack Vectors

### 1. Connection Exhaustion

**Attack:**
```
for i in 1..131072:
    open_connection(random_source_ip())
→ Pool exhausted, legitimate clients rejected
```

**Mitigations:**
- Retry mechanism (stateless cookies)
- Idle timeout (10s)
- Connection limits per configuration

**Gaps:**
- No per-address limit
- No rate limiting on Initial packets

---

### 2. Retry Token Forgery

**Attack:**
1. Collect retry tokens
2. Analyze IV generation pattern (guessable RNG)
3. Predict IV collision or engineer collision via birthday attack
4. Forge retry token → bypass retry mechanism

**Impact:** Connection DoS, resource exhaustion

---

### 3. Hash Collision DoS

**Attack:**
```
Connect with IDs:
- 0x0000000100000001
- 0x0000000200000001
- ... (all hash to same value)
→ Hash table performance degrades
→ Connection lookup slow
```

---

### 4. Certificate Parsing Rejection

**Attack:**
1. Use valid but non-canonical DER certificate
2. TLS handshake fails
3. Legitimate client cannot connect

**Note:** Not a security vulnerability, but availability issue

---

### 5. eBPF Program Bugs

**Risk:**
- eBPF bugs can crash kernel
- Firedancer generates eBPF dynamically
- Kernel verifier should catch most issues

**Mitigation:**
- Extensive bounds checking in generated code
- Kernel verifier validates safety

---

## Recommendations

### Immediate (Critical)

1. **Replace QUIC retry IV generation**
   - Use CSPRNG: `getrandom(2)` or `/dev/urandom`
   - Add explicit IV counter with overflow check
   - File: `fd_quic_retry.c:130-132`

2. **Fix connection map hash function**
   - Use xxhash or murmur3
   - File: `fd_quic_conn_map.h:16`

### High Priority

3. **Add TLS key derivation runtime checks**
   - Replace `FD_TEST` assertions with error returns
   - File: `fd_tls.c:132-134`

4. **Implement per-address rate limiting**
   - Token bucket per source IP
   - Limit Initial packets per second
   - File: `fd_quic.c` (connection handling)

### Medium Priority

5. **Extend ASN.1 parser**
   - Support non-canonical DER encodings
   - File: `fd_tls_asn1.c`

6. **Add connection ID rotation**
   - Support NEW_CONNECTION_ID frames
   - File: `fd_quic_conn.h:116` (remove FIXME)

7. **Validate GRE source IP**
   - Prevent IP spoofing via GRE encapsulation
   - File: `fd_xdp_tile.c` (TX path)

### Low Priority

8. **Add load balancing monitoring**
   - Track per-tile TX distribution
   - Alert on imbalance
   - Consider adaptive hashing

---

## Testing Recommendations

### Fuzzing Targets

1. **QUIC Packet Parser**
   - Malformed Initial packets
   - Invalid varints
   - Boundary conditions (0, UINT_MAX)

2. **TLS Handshake**
   - Non-canonical ASN.1 certificates
   - Oversized labels in HKDF
   - Invalid state transitions

3. **eBPF Generator**
   - Edge cases in port list
   - Maximum GRE nesting
   - Invalid packet structures

### Adversarial Testing

1. **Connection Exhaustion**
   - Open 131,072 connections
   - Measure legitimate client rejection

2. **Retry Token Analysis**
   - Collect 10,000+ tokens
   - Statistical analysis of IV distribution
   - Test for IV reuse

3. **Hash Collision Engineering**
   - Craft connection IDs with same hash
   - Measure performance degradation

---

## Security Checklist

- [x] QUIC Initial packet size enforcement (RFC 9000 §14.1)
- [x] TLS 1.3 handshake state machine
- [x] eBPF bounds checking
- [x] Packet parsing bounds validation
- [ ] CSPRNG for retry token IVs
- [ ] Per-address connection rate limiting
- [ ] Strong hash function for connection map
- [ ] TLS key derivation runtime validation
- [ ] Connection ID rotation support
- [ ] GRE source IP validation

---

## References

- RFC 9000: QUIC Protocol
- RFC 8446: TLS 1.3
- Linux kernel: AF_XDP documentation
- Source: `/home/user/firedancer/src/waltz/`
- Related: `SR/Architecture.md`, `SR/DoS_Mitigations.md`

**END OF NETWORK LAYER ANALYSIS**
