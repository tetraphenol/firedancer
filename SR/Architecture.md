# Firedancer Architecture - Security Analysis

**Analysis Date:** November 6, 2025
**Repository:** Firedancer/Agave Validator
**Focus:** System architecture and security boundaries

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Component Architecture](#component-architecture)
4. [Security Boundaries](#security-boundaries)
5. [Data Flow Security](#data-flow-security)
6. [Attack Surface Analysis](#attack-surface-analysis)
7. [Trust Boundaries](#trust-boundaries)

---

## Executive Summary

Firedancer is a high-performance Solana validator implemented in C, designed for security through:

- **Multi-process isolation** - Each tile runs in separate process
- **Kernel bypass networking** - AF_XDP for high-throughput packet processing
- **Minimal attack surface** - Restrictive sandboxing with seccomp-bpf
- **Hybrid architecture** - Firedancer network layer + Agave runtime ("Frankendancer")

### Critical Security Properties

- **Process isolation via tiles** - Prevents lateral movement between components
- **Shared memory IPC (Tango)** - Lock-free messaging with overflow detection
- **Cryptographic validation** - ED25519 signature verification before processing
- **Transactional state** - ACID-like semantics via Funk key-value store

---

## System Overview

### Deployment Model: Frankendancer

```
┌─────────────────────────────────────────────────────────┐
│                  FIREDANCER TILES                       │
│  ┌──────┐  ┌──────┐  ┌────────┐  ┌──────┐  ┌──────┐   │
│  │ NET  │→→│ QUIC │→→│ VERIFY │→→│DEDUP │→→│ PACK │   │
│  └──────┘  └──────┘  └────────┘  └──────┘  └──────┘   │
│  (XDP)     (TLS 1.3)  (ED25519)  (Sig     (Block      │
│                                    cache)  packing)     │
└─────────────────────────────────────────────────────────┘
                        ↓ Tango IPC
┌─────────────────────────────────────────────────────────┐
│               AGAVE VALIDATOR (child process)           │
│  ┌──────────┐  ┌─────────┐  ┌──────────┐              │
│  │ Runtime  │  │  sBPF   │  │ Consensus│              │
│  │ Executor │  │   VM    │  │  Tower   │              │
│  └──────────┘  └─────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

**Current State (v0.x):**
- Firedancer handles networking, signature verification, deduplication, block packing
- Agave handles transaction execution, consensus, state management
- Communication via shared memory (Funk + Tango)

**Future State (v1.x):**
- Full Firedancer implementation of all components
- No Agave dependency

---

## Component Architecture

### Layer 1: Infrastructure (UTIL)

**Purpose:** Low-level primitives, memory management, concurrency

**Key Components:**
- `util/wksp/` - Workspace allocator (quasi-lockfree)
- `util/shmem/` - Shared memory primitives
- `util/fibre/` - Lightweight fiber scheduler
- `util/tile/` - CPU core affinity management
- `util/sandbox/` - Sandboxing primitives (seccomp, namespaces)
- `util/simd/` - SIMD optimizations (AVX-512)

**Security Properties:**
- Pre-allocated memory (no runtime allocation)
- Huge/gigantic page backing (reduces TLB misses)
- Explicit memory ownership tracking
- **Security Boundary:** Memory isolation between tiles

---

### Layer 2: IPC Infrastructure (TANGO)

**Purpose:** Inter-tile communication with flow control

**Key Components:**
- `tango/mcache/` - Metadata cache (packet headers, signatures)
- `tango/dcache/` - Data cache (packet payloads)
- `tango/tcache/` - Tag cache (deduplication tags)
- `tango/fseq/` - Flow sequence tracking
- `tango/fctl/` - Flow control (backpressure)
- `tango/cnc/` - Command and control channel

**Message Flow:**
```
Producer Tile              Consumer Tile
    │                          │
    │  1. Allocate chunk       │
    │     in dcache            │
    │                          │
    │  2. Write metadata       │
    │     to mcache            │
    │                          │
    │  3. Atomic seq update ───→ 4. Poll mcache
    │                          │    via seq number
    │                          │
    │                          │ 5. Read metadata
    │                          │
    │                          │ 6. Read payload
    │                          │    from dcache
```

**Security Properties:**
- **Lockless communication** - Reduces DoS via lock contention
- **Sequence number ordering** - Detects message loss/reordering
- **Overrun detection** - Consumer knows if producer overwrote data
- **Flow control** - Prevents buffer exhaustion
- **Security Boundary:** Tiles cannot corrupt each other's message queues (read-only mapping)

**Vulnerabilities:**
- TOCTOU in mcache read (mitigated via sequence number check)
- See: `SR/IPC_Messaging.md` for details

---

### Layer 3: Network & Cryptography

#### Network Stack (WALTZ)

**Components:**
- `waltz/quic/` - QUIC protocol (RFC 9000)
- `waltz/tls/` - TLS 1.3 handshake
- `waltz/xdp/` - eBPF/AF_XDP kernel bypass
- `waltz/http/` - HTTP server (metrics, RPC)

**Packet Path:**
```
Physical NIC
    ↓
XDP eBPF Program (filters by port)
    ↓
AF_XDP Socket (kernel → userspace zero-copy)
    ↓
NET Tile (routes to QUIC/Shred tiles)
    ↓
QUIC Tile (TLS decryption, packet reassembly)
    ↓
VERIFY Tile (ED25519 signature verification)
```

**Security Properties:**
- **Zero-copy I/O** - Reduces memory copies, improves performance
- **Kernel bypass** - Packets go directly from NIC to userspace
- **Port-based filtering** - eBPF filters unwanted traffic in kernel
- **TLS 1.3** - Modern crypto with forward secrecy

**Attack Surface:**
- eBPF program bugs → kernel crash
- XDP driver vulnerabilities
- See: `SR/Network_Layer.md`

#### Cryptography (BALLET)

**Key Algorithms:**
- **ED25519** - Transaction signature verification (AVX-512 accelerated)
- **SHA-256/SHA-512** - Hashing for PoH, merkle trees
- **BLAKE3** - Fast hashing
- **AES-GCM** - Authenticated encryption (QUIC)
- **Reed-Solomon** - FEC for shreds

**Security Properties:**
- **Batch verification** - Up to 16 signatures per batch
- **Small-order point rejection** - Prevents invalid curve attacks
- **Constant-time operations** - Where documented
- **CAVP test vectors** - NIST compliance testing

**Vulnerabilities:**
- Non-canonical point acceptance (by design, matches Agave)
- See: `SR/Cryptography.md`

---

### Layer 4: State Management

**Components:**
- `funk/` - Transactional KV store
- `groove/` - Volume/disk storage abstraction
- `vinyl/` - Key-value index

**Architecture:**
```
Transaction Tree (in memory)
┌──────────────┐
│ Root (XID 0) │  ← Published state
└───────┬──────┘
        │
   ┌────┴────┐
   │ TXN 1   │  ← In-preparation transactions
   └────┬────┘
        │
   ┌────┴────┐
   │ TXN 2   │
   └─────────┘

Each record: (xid, key) → value
```

**Security Properties:**
- **Transaction isolation** - Each transaction has private view
- **Use-after-free detection** - Magic number + XID validation
- **Persistent storage** - Survives process crashes
- **Atomicity** - Transactions are all-or-nothing

**Vulnerabilities:**
- No transaction tree loop detection
- See: `SR/State_Management.md`

---

### Layer 5: Transaction Processing (DISCO)

**Pipeline:**
```
NET → QUIC → VERIFY → DEDUP → PACK → BANK → POH → SHRED → STORE
```

**Tile Responsibilities:**

1. **NET** - Raw packet I/O via AF_XDP
2. **QUIC** - Connection management, packet reassembly, TLS decryption
3. **VERIFY** - ED25519 signature verification
4. **DEDUP** - Duplicate transaction filtering (signature cache)
5. **PACK** - Transaction scheduling, block packing
6. **BANK** - Transaction execution (Agave runtime)
7. **POH** - Proof of History generation
8. **SHRED** - Block distribution (FEC encoding, Turbine protocol)
9. **STORE** - Block storage to disk

**Security Boundaries:**

| Boundary | Description | Enforcement |
|----------|-------------|-------------|
| NET → QUIC | Packet validation | XDP filter, QUIC parser |
| QUIC → VERIFY | Well-formed transaction extraction | Transaction parser |
| VERIFY → DEDUP | Cryptographic validation | ED25519 verification |
| DEDUP → PACK | Uniqueness guarantee | Signature cache lookup |
| PACK → BANK | Compute budget enforcement | Cost tracking |
| BANK → POH | Execution success | Transaction status |

**Critical Security Checks:**

- **Signature verification** (VERIFY) - Rejects invalid signatures
- **Deduplication** (DEDUP) - Prevents replay attacks
- **Compute limits** (PACK/BANK) - Prevents resource exhaustion
- **Account validation** (BANK) - Enforces account ownership

**Vulnerabilities:**
- Compute unit overflow in pack tile
- Bundle signature limit (4 max)
- See: `SR/Transaction_Processing.md`

---

### Layer 6: Consensus & Execution (CHOREO + FLAMENCO)

**Consensus Components (CHOREO):**
- `choreo/eqvoc/` - Equivocation (duplicate vote) detection
- `choreo/ghost/` - Fork choice (heaviest subtree)
- `choreo/tower/` - Vote lockouts (Tower BFT)
- `choreo/voter/` - Stake-weighted voting

**Runtime Components (FLAMENCO):**
- `flamenco/vm/` - sBPF virtual machine
- `flamenco/runtime/` - Transaction executor, account manager
- `flamenco/runtime/program/` - Syscall implementations

**Execution Security:**
```
┌─────────────────────────────────────┐
│      BPF Program (untrusted)        │
│  ┌────────────────────────────────┐ │
│  │   Syscall Interface            │ │ ← Validation boundary
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│      Runtime (trusted)              │
│  • Account access control           │
│  • Compute unit metering            │
│  • Memory bounds checking           │
└─────────────────────────────────────┘
```

**Security Properties:**
- **Memory isolation** - BPF programs cannot access arbitrary memory
- **Compute metering** - Programs have CU limits
- **Account validation** - Programs can only access declared accounts
- **Read-only enforcement** - Immutable accounts cannot be modified

**Vulnerabilities:**
- Binary search OOB in VM memory region lookup
- Account length race condition in CPI
- See: `SR/sBPF_VM_Runtime.md`

---

## Security Boundaries

### Process Isolation

**Model:** Each tile runs as separate process with restricted capabilities

```
┌─────────────────────────────────────────────────────────┐
│  Root Process (privileged)                             │
│  • Initializes XDP                                     │
│  • Creates shared memory                               │
│  • Drops to unprivileged user                          │
│  • Forks tile processes                                │
└─────────────────────────────────────────────────────────┘
        │
        ├──→ NET Tile (CAP_NET_RAW, CAP_NET_ADMIN)
        │    • Sandboxed: seccomp-bpf, user namespace
        │
        ├──→ QUIC Tile (minimal capabilities)
        │    • Sandboxed: seccomp-bpf
        │    • Read-only access to UMEM (RX packets)
        │
        ├──→ VERIFY Tile (minimal capabilities)
        │    • Sandboxed: seccomp-bpf
        │    • Read-only access to transaction data
        │
        └──→ ... (other tiles)
```

**Sandbox Configuration:**
- **User namespace** - Process believes it's root, but has no privileges
- **Network namespace** - Isolated network stack
- **Seccomp-bpf** - Whitelisted syscalls only
- **Capability dropping** - Removes all unnecessary capabilities
- **No new privileges** - Prevents privilege escalation via setuid
- **Landlock** - Filesystem access restrictions (kernel ≥5.13)

**Privilege Separation:**
- Tiles run as unprivileged user (configured in TOML)
- Shared memory mapped with appropriate permissions (RO vs RW)
- Example: QUIC tiles cannot write to VERIFY tile's signature cache

---

### Memory Isolation

**UMEM Regions:**
```
┌─────────────────────────────────────┐
│  RX Packets (from NIC)              │
│  • Read-only to app tiles           │ ← Security boundary
│  • Read-write to NET tile           │
│  • Shared with kernel (zero-copy)   │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│  TX Packets (to NIC)                │
│  • Read-only to NET tile            │ ← Security boundary
│  • Read-write to app tiles          │
└─────────────────────────────────────┘
```

**Workspace Isolation:**
- Each tile has private scratch workspace
- Shared workspaces have explicit permissions
- Magic number validation prevents corruption

---

### Network Isolation

**Ingress Path:**
```
Internet
   ↓
Firewall (operator configured)
   ↓
Physical NIC
   ↓
XDP eBPF Filter (port-based)  ← Kernel-level filtering
   ↓
AF_XDP Socket
   ↓
NET Tile (userspace)  ← Packet validation
   ↓
QUIC Tile  ← TLS decryption, connection limits
```

**Port Allocation:**
- **8001** - Gossip (Agave)
- **8003** - Shred (Turbine)
- **8899** - RPC (optional, should be firewalled)
- **9001** - TPU (non-QUIC transactions)
- **9007** - TPU QUIC (primary transaction ingress)

**Firewall Recommendations:**
- **Public:** 8001 (gossip), 8003 (shred), 9001 (TPU UDP), 9007 (TPU QUIC)
- **Private:** 8899 (RPC), 7999 (Prometheus metrics), 80 (GUI)
- **Blocked:** All other ports

---

## Data Flow Security

### Transaction Lifecycle

```
1. Client → QUIC Tile
   Security: TLS 1.3 encryption, connection limits

2. QUIC Tile → VERIFY Tile (via Tango mcache/dcache)
   Security: Transaction parsed, bounds checked

3. VERIFY Tile → DEDUP Tile
   Security: ED25519 signature verified

4. DEDUP Tile → PACK Tile
   Security: Duplicate filtered via signature cache

5. PACK Tile → BANK Tile (Agave)
   Security: Compute budget validated, block limits enforced

6. BANK Tile → Agave Runtime
   Security: sBPF VM sandboxing, account access control

7. Agave Runtime → FUNK
   Security: Transaction committed, state updated
```

### Vote Lifecycle

```
1. Validator → Gossip (UDP, no QUIC)
   Security: Vote signature verification

2. Gossip → Tower (consensus)
   Security: Equivocation detection

3. Tower → Ledger
   Security: Fork choice validation
```

---

## Attack Surface Analysis

### External Attack Surface

**Primary Ingress:**
1. **TPU QUIC (port 9007)** - Main transaction submission
   - Threat: DoS via connection exhaustion
   - Mitigation: Connection limits (131,072), idle timeout (10s), retry mechanism
2. **TPU UDP (port 9001)** - Non-QUIC transactions (votes, etc.)
   - Threat: Amplification attacks, packet flooding
   - Mitigation: Minimum 1200-byte Initial packet, rate limiting
3. **Gossip (port 8001)** - Peer discovery, vote dissemination
   - Threat: Sybil attacks, message flooding
   - Mitigation: Stake-weighted reputation, bloom filters
4. **Shred (port 8003)** - Block data distribution
   - Threat: Shred bombing, invalid FEC sets
   - Mitigation: FEC validation, merkle root verification

**Secondary Ingress:**
5. **RPC (port 8899)** - Query interface
   - Threat: Resource exhaustion, state query attacks
   - Mitigation: Should be firewalled, rate limiting recommended

**Management:**
6. **Metrics (port 7999)** - Prometheus endpoint
7. **GUI (port 80)** - Web interface
   - Threat: Information disclosure
   - Mitigation: Bind to 127.0.0.1 by default

### Internal Attack Surface

**Shared Memory:**
- Tango mcache/dcache/tcache
- Funk transactional store
- Threat: Memory corruption, race conditions
- Mitigation: Magic number validation, sequence number ordering

**IPC Messaging:**
- Threat: Message reordering, TOCTOU
- Mitigation: Overrun detection, atomic sequence updates

**Process Isolation:**
- Threat: Sandbox escape, capability escalation
- Mitigation: Seccomp-bpf, user namespaces, landlock

---

## Trust Boundaries

### Trusted Components

1. **Kernel** - Assumed secure (required for XDP, shared memory)
2. **Cryptographic primitives** - Assumed correct (ballet/)
3. **Configuration** - Assumed authentic (TOML file, keypairs)

### Untrusted Components

1. **Network input** - All packets assumed hostile
2. **BPF programs** - User-deployed smart contracts
3. **Peer validators** - Byzantine fault tolerance assumes up to 1/3 malicious

### Partially Trusted

1. **Agave runtime** - Trusted but legacy code, being replaced
2. **Shared memory** - Trusted within validator, but requires synchronization

---

## Recommended Security Hardening

### System Configuration

1. **Firewall:**
   ```bash
   # Public ports
   ufw allow 8001/tcp  # Gossip
   ufw allow 8003/udp  # Shred
   ufw allow 9001/udp  # TPU UDP
   ufw allow 9007/udp  # TPU QUIC

   # Private ports (localhost only)
   ufw deny 8899/tcp   # RPC
   ufw deny 7999/tcp   # Metrics
   ufw deny 80/tcp     # GUI
   ```

2. **Kernel hardening:**
   ```bash
   # Increase max locked memory for huge pages
   echo "firedancer soft memlock unlimited" >> /etc/security/limits.conf
   echo "firedancer hard memlock unlimited" >> /etc/security/limits.conf

   # Disable core dumps globally
   echo "* hard core 0" >> /etc/security/limits.conf
   ```

3. **User isolation:**
   ```bash
   # Create dedicated user with no privileges
   useradd -r -s /bin/false -M firedancer
   ```

### Monitoring

1. **Process monitoring:**
   - Alert if any tile process dies
   - Monitor for unexpected restarts
   - Track memory usage (should be stable, pre-allocated)

2. **Network monitoring:**
   - Alert on abnormal connection counts
   - Monitor packet drop rates (XDP, QUIC)
   - Track signature verification failures

3. **State monitoring:**
   - Monitor funk transaction depth
   - Track equivocation proofs
   - Alert on ghost pool exhaustion

---

## References

- Firedancer docs: `/home/user/firedancer/book/`
- Source code: `/home/user/firedancer/src/`
- Configuration: `/home/user/firedancer/src/app/fdctl/config/default.toml`
- Related analyses:
  - `SR/Network_Layer.md` - QUIC, TLS, XDP details
  - `SR/Cryptography.md` - Ballet implementations
  - `SR/sBPF_VM_Runtime.md` - Execution security
  - `SR/IPC_Messaging.md` - Tango details
  - `SR/Transaction_Processing.md` - Pipeline security

---

**END OF ARCHITECTURE ANALYSIS**
