# Firedancer/Agave Validator - Comprehensive Security Assessment Checklist

**Version:** 1.0
**Date:** November 15, 2025
**Scope:** Frankendancer (v0.x) + Agave runtime, with considerations for pure Firedancer (v1.x)
**Methodology:** White-box testing with source code analysis and dynamic runtime testing
**Test Environment:** Local fddev node available for runtime testing

---

## Document Purpose

This checklist provides an exhaustive list of security checks to be performed during a comprehensive security assessment of the Firedancer validator. Each item represents a specific vulnerability class, attack vector, or security control that should be verified. Items are organized by component and security domain, broken down into highly specific, actionable checks that can be ticked off as testing progresses.

---

## Table of Contents

1. [Network Layer Security](#1-network-layer-security)
2. [Cryptography & Signature Verification](#2-cryptography--signature-verification)
3. [Transaction Processing Pipeline](#3-transaction-processing-pipeline)
4. [sBPF Virtual Machine & Runtime](#4-sbpf-virtual-machine--runtime)
5. [Consensus Layer](#5-consensus-layer)
6. [State Management](#6-state-management)
7. [IPC & Shared Memory](#7-ipc--shared-memory)
8. [Memory Safety & Process Isolation](#8-memory-safety--process-isolation)
9. [Denial of Service Protections](#9-denial-of-service-protections)
10. [Configuration & Deployment](#10-configuration--deployment)
11. [Agave Runtime Integration](#11-agave-runtime-integration)
12. [Supply Chain & Build Security](#12-supply-chain--build-security)

---

## 1. Network Layer Security

### 1.1 QUIC Protocol Implementation

#### 1.1.1 Connection Management
- [ ] Verify connection pool exhaustion handling when max connections (131,072 default) reached
- [ ] Test connection allocation failure gracefully rejects new connections without crash
- [ ] Validate idle timeout (1s default) properly closes inactive connections
- [ ] Confirm connection state machine prevents invalid state transitions
- [ ] Test connection ID collision handling with crafted IDs
- [ ] Verify connection migration support (currently FIXME - may fail on NAT rebinding)
- [ ] Test simultaneous connection attempts from same IP address
- [ ] Validate connection cleanup releases all associated resources

#### 1.1.2 Retry Token Mechanism
- [ ] Verify retry token AES-GCM encryption uses cryptographically secure IV generation
- [ ] Test retry token validation rejects tokens with incorrect IP/port binding
- [ ] Confirm retry token expiration (1s default) is properly enforced
- [ ] Test replay attack resistance - reusing same token should fail
- [ ] Validate retry token forgery protection - modified tokens rejected
- [ ] Test stateless retry prevents resource allocation before token validation
- [ ] Verify amplification attack mitigation - Initial packet minimum 1200 bytes enforced
- [ ] Test retry token under IV reuse scenario (current vulnerability - see `fd_quic_retry.h:82-87`)

#### 1.1.3 Packet Parsing
- [ ] Fuzz QUIC packet parser with malformed packets (invalid lengths, bad opcodes)
- [ ] Test varint decoding with maximum values and edge cases
- [ ] Verify bounds checking on all variable-length fields
- [ ] Test packet reassembly with out-of-order fragments
- [ ] Validate header parsing rejects packets with invalid flags
- [ ] Test frame parsing for all QUIC frame types
- [ ] Verify packet decryption failure handling
- [ ] Test packet with valid header but corrupted payload

#### 1.1.4 Handshake Security
- [ ] Test TLS 1.3 handshake with invalid certificates
- [ ] Verify certificate validation rejects expired certificates
- [ ] Test certificate chain validation
- [ ] Validate handshake state machine prevents skipping states
- [ ] Test handshake timeout handling
- [ ] Verify key derivation uses proper HKDF implementation
- [ ] Test handshake with mismatched protocol versions
- [ ] Validate ClientHello parsing rejects oversized extensions

#### 1.1.5 Stream Management
- [ ] Test stream creation up to configured limit
- [ ] Verify stream ID exhaustion handling
- [ ] Test bidirectional vs unidirectional stream enforcement
- [ ] Validate stream flow control enforcement
- [ ] Test stream closure handling (both clean and abrupt)
- [ ] Verify stream data ordering guarantees
- [ ] Test concurrent stream operations
- [ ] Validate stream priority handling

### 1.2 TLS 1.3 Implementation

#### 1.2.1 Certificate Validation
- [ ] Test ASN.1 parser with non-canonical DER encodings (known issue - `fd_tls_asn1.h:14-24`)
- [ ] Verify certificate CN/SAN validation
- [ ] Test certificate with invalid signature
- [ ] Validate certificate chain depth limits
- [ ] Test self-signed certificate rejection (if applicable)
- [ ] Verify CRL/OCSP checking (if implemented)
- [ ] Test certificate with future/past validity dates
- [ ] Validate certificate key usage constraints

#### 1.2.2 Key Exchange
- [ ] Verify ECDHE key exchange parameter validation
- [ ] Test X25519 key exchange with invalid points
- [ ] Validate shared secret derivation
- [ ] Test handshake with weak cipher suites (should be rejected)
- [ ] Verify perfect forward secrecy implementation
- [ ] Test session resumption security
- [ ] Validate key schedule derivation matches RFC 8446

#### 1.2.3 Encryption/Decryption
- [ ] Test AES-GCM encryption with various payload sizes
- [ ] Verify authentication tag validation
- [ ] Test nonce/IV uniqueness enforcement
- [ ] Validate encryption context handling
- [ ] Test decryption failure handling
- [ ] Verify record padding validation
- [ ] Test maximum record size enforcement (16KB)
- [ ] Validate ChaCha20-Poly1305 support (if enabled)

### 1.3 XDP/AF_XDP Kernel Bypass

#### 1.3.1 eBPF Program Security
- [ ] Review XDP program for bounds checking on packet access
- [ ] Verify eBPF verifier accepts the XDP program
- [ ] Test XDP program with malformed Ethernet frames
- [ ] Validate port-based filtering works correctly
- [ ] Test XDP program resource limits (maps, instructions)
- [ ] Verify XDP program doesn't leak kernel memory
- [ ] Test XDP program with jumbo frames
- [ ] Validate XDP program handles VLAN tags correctly

#### 1.3.2 UMEM Management
- [ ] Test UMEM allocation failure handling
- [ ] Verify UMEM bounds checking on packet read/write
- [ ] Test UMEM exhaustion scenarios
- [ ] Validate UMEM memory mapping permissions (RO vs RW)
- [ ] Test UMEM chunk alignment requirements
- [ ] Verify UMEM sharing between RX/TX queues
- [ ] Test UMEM cleanup on process termination
- [ ] Validate huge page backing works correctly

#### 1.3.3 Zero-Copy I/O
- [ ] Test packet receive with AF_XDP socket
- [ ] Verify zero-copy actually occurs (no memcpy)
- [ ] Test packet transmit with AF_XDP socket
- [ ] Validate fill queue operation
- [ ] Test completion queue operation
- [ ] Verify queue wraparound handling
- [ ] Test descriptor ring exhaustion
- [ ] Validate packet ownership tracking

### 1.4 Network Tile

#### 1.4.1 Packet Routing
- [ ] Test packet routing to correct QUIC tile based on connection ID
- [ ] Verify load balancing across multiple QUIC tiles
- [ ] Test packet drops under high load
- [ ] Validate packet priority handling
- [ ] Test routing with invalid connection IDs
- [ ] Verify metrics tracking for routed packets
- [ ] Test routing table updates
- [ ] Validate packet filtering by protocol

#### 1.4.2 Resource Management
- [ ] Test network tile under sustained high packet rate
- [ ] Verify packet buffer exhaustion handling
- [ ] Test CPU affinity pinning
- [ ] Validate memory usage stays bounded
- [ ] Test network tile restart after crash
- [ ] Verify no packet loss during normal operation
- [ ] Test graceful shutdown
- [ ] Validate error recovery mechanisms

---

## 2. Cryptography & Signature Verification

### 2.1 ED25519 Signature Verification

#### 2.1.1 Signature Validation
- [ ] Test ED25519 verification with valid signatures
- [ ] Verify signature verification rejects invalid signatures
- [ ] Test signature malleability attacks (non-canonical R encoding accepted by design)
- [ ] Validate small-order point rejection (`fd_ed25519_user.c:194-199`)
- [ ] Test signature with invalid scalar values
- [ ] Verify signature verification with zero public key
- [ ] Test signature replay across different messages
- [ ] Validate batch verification correctness

#### 2.1.2 Batch Verification
- [ ] Test batch verification with 1-16 signatures
- [ ] Verify batch fails if any signature is invalid
- [ ] Test batch verification performance vs individual
- [ ] Validate batch with duplicate signatures
- [ ] Test batch with same message, different signatures
- [ ] Verify early rejection on validation failure
- [ ] Test batch verification with maximum batch size
- [ ] Validate batch verification with zero batch size

#### 2.1.3 Side-Channel Resistance
- [ ] Perform timing analysis on signature verification
- [ ] Test constant-time properties of scalar operations
- [ ] Verify point decompression timing consistency
- [ ] Test signature verification under cache attacks
- [ ] Validate branch prediction independence
- [ ] Test with intentionally invalid points to check timing
- [ ] Verify memory access patterns are data-independent
- [ ] Validate AVX-512 implementation for side-channel resistance

#### 2.1.4 Public Key Validation
- [ ] Test public key validation with invalid curve points
- [ ] Verify small-order public key rejection
- [ ] Test public key with invalid encoding
- [ ] Validate public key decompression
- [ ] Test public key at infinity (should be rejected)
- [ ] Verify cofactor clearing (if applicable)
- [ ] Test public key with non-canonical encoding (accepted by design)
- [ ] Validate public key bounds checking

### 2.2 Hash Functions

#### 2.2.1 SHA-256/SHA-512
- [ ] Test SHA implementations against NIST test vectors
- [ ] Verify correct padding for various message lengths
- [ ] Test hash of empty input
- [ ] Validate hash of maximum length input
- [ ] Test incremental hashing (append operations)
- [ ] Verify hash state clearing after finalization
- [ ] Test SIMD-accelerated implementation correctness
- [ ] Validate endianness handling

#### 2.2.2 BLAKE3
- [ ] Test BLAKE3 implementation against specification
- [ ] Verify keyed hashing mode
- [ ] Test key derivation mode
- [ ] Validate incremental updates
- [ ] Test variable output length
- [ ] Verify parallelism correctness
- [ ] Test BLAKE3 with maximum tree depth
- [ ] Validate against reference implementation

#### 2.2.3 Proof of History (PoH)
- [ ] Test PoH append operation correctness
- [ ] Verify PoH timing oracle (variable-time by design - `fd_poh.c`)
- [ ] Test PoH with zero iterations
- [ ] Validate PoH with maximum iterations
- [ ] Test PoH hash chaining
- [ ] Verify PoH state persistence
- [ ] Test PoH tick generation
- [ ] Validate PoH verification

### 2.3 AES-GCM

#### 2.3.1 Encryption
- [ ] Test AES-128-GCM encryption with various plaintext sizes
- [ ] Verify IV/nonce uniqueness enforcement
- [ ] Test associated data authentication
- [ ] Validate encryption with empty plaintext
- [ ] Test encryption with maximum plaintext size
- [ ] Verify key schedule generation
- [ ] Test multiple backends (AES-NI, portable)
- [ ] Validate authentication tag generation

#### 2.3.2 Decryption
- [ ] Test AES-GCM decryption with valid ciphertext
- [ ] Verify authentication tag validation rejects modified ciphertext
- [ ] Test decryption with modified AAD
- [ ] Validate decryption with wrong key
- [ ] Test decryption with wrong nonce
- [ ] Verify constant-time tag comparison
- [ ] Test decryption failure handling
- [ ] Validate ciphertext length checks

### 2.4 Reed-Solomon FEC

#### 2.4.1 Encoding
- [ ] Test FEC encoding for various data sizes
- [ ] Verify parity shard generation
- [ ] Test encoding with maximum shards
- [ ] Validate encoding with minimum shards
- [ ] Test encoding performance
- [ ] Verify systematic encoding (data shards unchanged)
- [ ] Test encoding with single data shard
- [ ] Validate encoding determinism

#### 2.4.2 Decoding
- [ ] Test FEC decoding with erasures
- [ ] Verify decoding with maximum erasures
- [ ] Test decoding with corrupted shards
- [ ] Validate decoding with partial shards
- [ ] Test decoding failure scenarios
- [ ] Verify decoded data matches original
- [ ] Test decoding with invalid shard indices
- [ ] Validate decoding with mixed erasures and errors

---

## 3. Transaction Processing Pipeline

### 3.1 Transaction Parsing

#### 3.1.1 Structure Validation
- [ ] Fuzz transaction parser with malformed transactions
- [ ] Test transaction with invalid version
- [ ] Verify signature count validation (max 127)
- [ ] Test transaction with zero signatures
- [ ] Validate account count limits (max 128)
- [ ] Test transaction with zero accounts
- [ ] Verify instruction count limits (max 64)
- [ ] Test transaction with zero instructions
- [ ] Validate transaction size limits (MTU 1232 bytes)
- [ ] Test oversized transaction rejection

#### 3.1.2 Signature Parsing
- [ ] Test signature offset validation
- [ ] Verify signature extraction bounds checking
- [ ] Test transaction with duplicate signatures
- [ ] Validate signature ordering
- [ ] Test compact array length encoding
- [ ] Verify signature count mismatch detection
- [ ] Test transaction with invalid signature format
- [ ] Validate parse failure handling (`fd_verify_tile.c:117-119` - current issue)

#### 3.1.3 Account Parsing
- [ ] Test account address parsing
- [ ] Verify read-only account flags
- [ ] Test writable account flags
- [ ] Validate signer account flags
- [ ] Test account deduplication
- [ ] Verify account index validation
- [ ] Test transaction with invalid account references
- [ ] Validate account ordering enforcement

#### 3.1.4 Instruction Parsing
- [ ] Test instruction program ID extraction
- [ ] Verify instruction account indices validation
- [ ] Test instruction data length validation
- [ ] Validate instruction data extraction
- [ ] Test instruction with no accounts
- [ ] Verify instruction with maximum accounts
- [ ] Test instruction with empty data
- [ ] Validate instruction ordering

### 3.2 Signature Verification Tile

#### 3.2.1 Verification Pipeline
- [ ] Test signature verification throughput
- [ ] Verify batch verification optimization
- [ ] Test verification failure handling
- [ ] Validate metrics tracking
- [ ] Test verification under high load
- [ ] Verify CPU affinity effectiveness
- [ ] Test verification with mixed valid/invalid signatures
- [ ] Validate signature cache integration

#### 3.2.2 Signature Cache
- [ ] Test signature cache with 4M entries (default)
- [ ] Verify cache hit rate under load
- [ ] Test cache eviction policy
- [ ] Validate cache key generation
- [ ] Test cache collision handling
- [ ] Verify cache invalidation
- [ ] Test cache persistence across restarts
- [ ] Validate cache memory usage bounds

### 3.3 Deduplication Tile

#### 3.3.1 Duplicate Detection
- [ ] Test dedup with duplicate transaction signatures
- [ ] Verify dedup cache correctness
- [ ] Test bundle transaction handling
- [ ] Validate bundle signature limit (currently 4 max - `fd_dedup_tile.c:42-45`)
- [ ] Test bundle with >4 signatures (should fail gracefully)
- [ ] Verify dedup under high transaction rate
- [ ] Test dedup with intentional replay attacks
- [ ] Validate dedup metrics accuracy

#### 3.3.2 Gossip Vote Handling
- [ ] Test gossip vote dedup path
- [ ] Verify gossip vote size validation
- [ ] Test malformed gossip vote handling
- [ ] Validate gossip vote routing
- [ ] Test gossip vote under high rate
- [ ] Verify gossip vote doesn't bypass signature verification
- [ ] Test gossip vote with invalid signature
- [ ] Validate gossip vote metrics

### 3.4 Block Packing Tile

#### 3.4.1 Transaction Scheduling
- [ ] Test transaction scheduling algorithms
- [ ] Verify priority fee ordering
- [ ] Test compute unit budget enforcement
- [ ] Validate block size limits
- [ ] Test transaction conflicts detection
- [ ] Verify account lock handling
- [ ] Test transaction expiration
- [ ] Validate transaction ordering determinism

#### 3.4.2 Compute Budget Tracking
- [ ] Test compute unit accumulation (check for overflow - `fd_pack.c`)
- [ ] Verify per-block CU limit (100M SIMD-0286)
- [ ] Test per-transaction CU limit (1.4M max)
- [ ] Validate per-account writable limit (12M)
- [ ] Test CU overflow attack scenario
- [ ] Verify CU metering accuracy
- [ ] Test block packing with CU limit reached
- [ ] Validate CU estimation correctness

#### 3.4.3 Block Construction
- [ ] Test block construction with various transaction counts
- [ ] Verify block header generation
- [ ] Test block with maximum transactions
- [ ] Validate block with zero transactions
- [ ] Test block hash calculation
- [ ] Verify block parent hash linkage
- [ ] Test block timestamp validation
- [ ] Validate block leader signature

---

## 4. sBPF Virtual Machine & Runtime

### 4.1 VM Instruction Validation

#### 4.1.1 Opcode Validation
- [ ] Test all 256 opcodes for correct handling
- [ ] Verify invalid opcode rejection
- [ ] Test instruction length validation
- [ ] Validate instruction alignment requirements
- [ ] Test jump instruction bounds checking
- [ ] Verify call instruction validation
- [ ] Test exit instruction handling
- [ ] Validate instruction count limits

#### 4.1.2 Register Validation
- [ ] Test register index bounds (0-15)
- [ ] Verify r10 (stack pointer) protection
- [ ] Test register initialization
- [ ] Validate register value ranges
- [ ] Test register spill/fill operations
- [ ] Verify register aliasing (32-bit vs 64-bit)
- [ ] Test register clobbering between functions
- [ ] Validate register preservation across calls

#### 4.1.3 Immediate Values
- [ ] Test immediate value sign extension
- [ ] Verify immediate value range validation
- [ ] Test large immediate values
- [ ] Validate immediate encoding
- [ ] Test immediate in arithmetic operations
- [ ] Verify immediate in memory operations
- [ ] Test immediate in jump operations
- [ ] Validate immediate overflow handling

### 4.2 Memory Access Validation

#### 4.2.1 Region Validation
- [ ] Test memory region initialization
- [ ] Verify binary search OOB fix (`fd_vm_private.h:296-310` - when regions_cnt==0)
- [ ] Test memory access with zero regions
- [ ] Validate region bounds checking
- [ ] Test region overlap detection
- [ ] Verify region permissions (RO/RW)
- [ ] Test region resizing validation
- [ ] Validate region growth limits

#### 4.2.2 Load/Store Operations
- [ ] Test all load instruction variants (ld, ldh, ldb, ldx)
- [ ] Verify all store instruction variants (st, sth, stb, stx)
- [ ] Test unaligned memory access handling
- [ ] Validate out-of-bounds read detection
- [ ] Test out-of-bounds write detection
- [ ] Verify NULL pointer dereference detection
- [ ] Test memory access across region boundaries
- [ ] Validate atomic memory operations

#### 4.2.3 Stack Operations
- [ ] Test stack pointer (r10) bounds checking
- [ ] Verify stack frame allocation
- [ ] Test stack overflow detection
- [ ] Validate stack underflow detection
- [ ] Test stack alignment requirements
- [ ] Verify stack frame management across calls
- [ ] Test maximum stack depth
- [ ] Validate stack initialization

### 4.3 Arithmetic & Logic Operations

#### 4.3.1 Integer Arithmetic
- [ ] Test addition with overflow
- [ ] Verify subtraction with underflow
- [ ] Test multiplication overflow
- [ ] Validate division by zero handling
- [ ] Test modulo by zero handling
- [ ] Verify signed division overflow (INT_MIN / -1)
- [ ] Test 32-bit vs 64-bit arithmetic
- [ ] Validate arithmetic result bounds

#### 4.3.2 Bitwise Operations
- [ ] Test AND, OR, XOR operations
- [ ] Verify left shift operations
- [ ] Test right shift operations (logical and arithmetic)
- [ ] Validate shift with large shift amounts (FIXME noted - `fd_vm_interp_core.c:972`)
- [ ] Test bit manipulation correctness
- [ ] Verify endianness conversions
- [ ] Test rotate operations (if applicable)
- [ ] Validate bitwise operation edge cases

### 4.4 Control Flow

#### 4.4.1 Jump Operations
- [ ] Test conditional jumps (jeq, jne, jgt, jge, jlt, jle)
- [ ] Verify unconditional jump (ja)
- [ ] Test jump target validation
- [ ] Validate jump to invalid PC
- [ ] Test backward jumps (loop detection)
- [ ] Verify forward jumps
- [ ] Test jump out of program bounds
- [ ] Validate jump instruction encoding

#### 4.4.2 Function Calls
- [ ] Test call instruction to valid function
- [ ] Verify call to invalid function (not in calldests)
- [ ] Test call stack depth limits
- [ ] Validate return instruction
- [ ] Test return from entry function
- [ ] Verify function arguments passing
- [ ] Test recursive calls (if allowed)
- [ ] Validate call/return stack unwinding

### 4.5 Syscall Interface

#### 4.5.1 Syscall Registration
- [ ] Test syscall hash table construction
- [ ] Verify syscall lookup by hash
- [ ] Test invalid syscall invocation
- [ ] Validate syscall availability by feature set
- [ ] Test syscall versioning
- [ ] Verify syscall permissions
- [ ] Test syscall with invalid arguments
- [ ] Validate syscall return value handling

#### 4.5.2 Memory Translation Syscalls
- [ ] Test sol_memcpy_ syscall
- [ ] Verify sol_memmove_ syscall
- [ ] Test sol_memcmp_ syscall
- [ ] Validate sol_memset_ syscall
- [ ] Test memory syscalls with overlapping regions
- [ ] Verify memory syscalls bounds checking
- [ ] Test memory syscalls with zero length
- [ ] Validate memory syscalls with maximum length

#### 4.5.3 Logging Syscalls
- [ ] Test sol_log_ syscall
- [ ] Verify sol_log_64_ syscall
- [ ] Test sol_log_compute_units_ syscall
- [ ] Validate log message length limits
- [ ] Test logging with invalid string pointers
- [ ] Verify log rate limiting
- [ ] Test log truncation
- [ ] Validate log output correctness

#### 4.5.4 Account Access Syscalls
- [ ] Test sol_get_account_info syscall
- [ ] Verify account data pointer validation
- [ ] Test account lamports read/write
- [ ] Validate account owner checks
- [ ] Test account rent-exempt balance
- [ ] Verify account executable flag
- [ ] Test account data resize
- [ ] Validate account signer checks

#### 4.5.5 Cryptographic Syscalls
- [ ] Test sol_sha256 syscall
- [ ] Verify sol_keccak256 syscall
- [ ] Test sol_blake3 syscall
- [ ] Validate sol_verify_signature syscall
- [ ] Test curve25519 operations
- [ ] Verify hash syscall input validation
- [ ] Test cryptographic syscall performance
- [ ] Validate syscall compute unit costs

#### 4.5.6 Cross-Program Invocation (CPI)
- [ ] Test sol_invoke_signed syscall
- [ ] Verify CPI account list validation
- [ ] Test CPI instruction construction
- [ ] Validate CPI privilege escalation prevention
- [ ] Test CPI depth limits (max 4)
- [ ] Verify CPI account length race condition fix (`fd_vm_syscall_cpi_common.c:163`)
- [ ] Test CPI with duplicate accounts
- [ ] Validate CPI signer seeds verification
- [ ] Test CPI compute unit consumption
- [ ] Verify CPI return data handling

### 4.6 Compute Unit Metering

#### 4.6.1 CU Tracking
- [ ] Test CU consumption for each instruction
- [ ] Verify CU depletion triggers execution halt
- [ ] Test CU request via compute budget program
- [ ] Validate CU refund on early exit
- [ ] Test CU metering accuracy
- [ ] Verify CU limit enforcement (1.4M max)
- [ ] Test CU consumption in nested calls
- [ ] Validate CU overflow prevention

#### 4.6.2 Heap Management
- [ ] Test heap allocation syscalls
- [ ] Verify heap size limits (32KB default, 256KB max)
- [ ] Test heap exhaustion handling
- [ ] Validate heap alignment requirements
- [ ] Test heap memory initialization
- [ ] Verify heap bounds checking
- [ ] Test concurrent heap allocations
- [ ] Validate heap deallocation

### 4.7 Program Loading

#### 4.7.1 ELF Validation
- [ ] Test ELF header validation
- [ ] Verify program header validation
- [ ] Test section header validation
- [ ] Validate text section alignment (FIXME - must be multiple of 8 - `fd_bpf_loader_program.c:193`)
- [ ] Test ELF with invalid magic number
- [ ] Verify ELF architecture check
- [ ] Test oversized ELF handling
- [ ] Validate ELF relocation processing

#### 4.7.2 Program Deployment
- [ ] Test BPF loader v1 deployment
- [ ] Verify BPF loader v2 deployment
- [ ] Test BPF loader v3 (upgradeable) deployment
- [ ] Validate BPF loader v4 deployment
- [ ] Test program upgrade authorization
- [ ] Verify program finalization
- [ ] Test program close
- [ ] Validate program account ownership

#### 4.7.3 Program Verification
- [ ] Test VM validator on valid programs
- [ ] Verify validator rejects invalid programs
- [ ] Test validator detects infinite loops
- [ ] Validate validator checks jump targets
- [ ] Test validator verifies register usage
- [ ] Verify validator checks function signatures
- [ ] Test validator performance on large programs
- [ ] Validate validator error messages

---

## 5. Consensus Layer

### 5.1 Equivocation Detection

#### 5.1.1 Double-Vote Detection
- [ ] Test equivocation detection with conflicting votes
- [ ] Verify gossip layer lacks double-vote check (`fd_gossip.c` - current gap)
- [ ] Test equivocation proof generation
- [ ] Validate equivocation proof verification
- [ ] Test equivocation slashing (if implemented)
- [ ] Verify equivocation evidence propagation
- [ ] Test equivocation detection under network partition
- [ ] Validate equivocation pool capacity

#### 5.1.2 FEC Proof Pool
- [ ] Test FEC proof pool insertion
- [ ] Verify FEC proof pool eviction (currently missing - `fd_eqvoc.c:113-115`)
- [ ] Test FEC proof pool exhaustion
- [ ] Validate FEC proof assembly from chunks
- [ ] Test FEC proof with missing chunks
- [ ] Verify FEC proof TTL handling
- [ ] Test FEC proof pool under attack (intentional flooding)
- [ ] Validate FEC proof chunk deduplication

### 5.2 Fork Choice (Ghost)

#### 5.2.1 Ghost Algorithm
- [ ] Test Ghost fork choice with single chain
- [ ] Verify Ghost fork choice with multiple forks
- [ ] Test Ghost weight calculation
- [ ] Validate Ghost heaviest subtree selection
- [ ] Test Ghost with Byzantine validators
- [ ] Verify Ghost pool exhaustion handling (`fd_ghost.c:299-300`)
- [ ] Test Ghost fork pruning
- [ ] Validate Ghost vote processing

#### 5.2.2 Fork Management
- [ ] Test fork creation and tracking
- [ ] Verify fork resolution
- [ ] Test fork depth limits
- [ ] Validate fork switch handling
- [ ] Test fork with missing ancestors
- [ ] Verify fork orphaning
- [ ] Test fork pruning logic
- [ ] Validate fork rollback scenarios

### 5.3 Tower BFT Voting

#### 5.3.1 Vote Validation
- [ ] Test vote signature verification
- [ ] Verify vote slot validation
- [ ] Test vote hash validation
- [ ] Validate vote timestamp checking
- [ ] Test vote from unauthorized validator
- [ ] Verify vote lockout enforcement
- [ ] Test vote switching rules
- [ ] Validate vote expiration

#### 5.3.2 Lockout Mechanism
- [ ] Test lockout calculation (2^n slots)
- [ ] Verify lockout doubling on consecutive votes
- [ ] Test lockout expiration
- [ ] Validate lockout override rules
- [ ] Test maximum lockout depth
- [ ] Verify lockout persistence
- [ ] Test lockout under fork switch
- [ ] Validate lockout reset conditions

### 5.4 Shred Processing

#### 5.4.1 Shred Validation
- [ ] Test shred signature verification
- [ ] Verify shred slot validation
- [ ] Test shred index validation
- [ ] Validate shred FEC set consistency
- [ ] Test shred with invalid merkle proof
- [ ] Verify shred duplicate detection
- [ ] Test shred reassembly
- [ ] Validate shred version checking

#### 5.4.2 Merkle Root Validation
- [ ] Test CMR chaining between shreds
- [ ] Verify CMR overwriting protection (`fd_reasm.c:186-198` - current issue)
- [ ] Test invalid parent hash handling
- [ ] Validate merkle proof verification
- [ ] Test merkle tree construction
- [ ] Verify merkle root mismatch detection
- [ ] Test merkle root caching
- [ ] Validate merkle root rollback

#### 5.4.3 FEC Decoding
- [ ] Test FEC decoding with erasures
- [ ] Verify FEC decoding with maximum erasures
- [ ] Test FEC decoding failure handling
- [ ] Validate FEC parity shard verification
- [ ] Test FEC with corrupted shreds
- [ ] Verify FEC reconstruction correctness
- [ ] Test FEC under attack (invalid parity shreds)
- [ ] Validate FEC performance under load

### 5.5 Gossip Protocol

#### 5.5.1 Peer Discovery
- [ ] Test peer discovery via gossip
- [ ] Verify peer validation
- [ ] Test peer reputation scoring
- [ ] Validate peer pruning
- [ ] Test Sybil attack resistance
- [ ] Verify peer connection limits
- [ ] Test peer ban mechanism
- [ ] Validate peer list synchronization

#### 5.5.2 Message Propagation
- [ ] Test gossip message fanout
- [ ] Verify gossip message deduplication
- [ ] Test gossip message rate limiting
- [ ] Validate gossip message signatures
- [ ] Test gossip message TTL
- [ ] Verify gossip bloom filter
- [ ] Test gossip under network partition
- [ ] Validate gossip message prioritization

#### 5.5.3 CRDS (Cluster Replicated Data Store)
- [ ] Test CRDS update propagation
- [ ] Verify CRDS version vector
- [ ] Test CRDS conflict resolution
- [ ] Validate CRDS entry expiration
- [ ] Test CRDS pruning
- [ ] Verify CRDS data integrity
- [ ] Test CRDS under Byzantine updates
- [ ] Validate CRDS synchronization

---

## 6. State Management

### 6.1 Funk (Transactional KV Store)

#### 6.1.1 Transaction Isolation
- [ ] Test transaction tree construction
- [ ] Verify parent-child transaction relationships
- [ ] Test transaction isolation (no cross-txn reads)
- [ ] Validate transaction cycle detection
- [ ] Test transaction depth limits
- [ ] Verify transaction rollback
- [ ] Test transaction commit atomicity
- [ ] Validate transaction conflict detection

#### 6.1.2 Record Management
- [ ] Test record insertion
- [ ] Verify record update (copy-on-write)
- [ ] Test record deletion
- [ ] Validate record key hashing
- [ ] Test record value size limits (28-bit)
- [ ] Verify record use-after-free detection
- [ ] Test record lookup performance
- [ ] Validate record magic number checks

#### 6.1.3 Hash Function Security
- [ ] Test hash function on 64-bit platforms (xxHash3)
- [ ] Verify hash function on 32-bit platforms (vulnerable to HashDoS - `fd_funk_base.h:203`)
- [ ] Test hash collision handling
- [ ] Validate hash distribution
- [ ] Test intentional hash collision attack (32-bit)
- [ ] Verify hash seed randomization
- [ ] Test hash function performance
- [ ] Validate hash function matches xxHash3 spec

### 6.2 Groove (Volume Storage)

#### 6.2.1 Volume Management
- [ ] Test volume creation (1GB fixed size)
- [ ] Verify volume initialization
- [ ] Test volume header validation
- [ ] Validate volume magic number
- [ ] Test volume corruption detection
- [ ] Verify volume metadata
- [ ] Test volume persistence
- [ ] Validate volume cleanup

#### 6.2.2 Data Storage
- [ ] Test data write to volume
- [ ] Verify data read from volume
- [ ] Test data size validation (24-bit limits)
- [ ] Validate data alignment
- [ ] Test guard region protection (3968 bytes)
- [ ] Verify data bounds checking
- [ ] Test data overwrite scenarios
- [ ] Validate data integrity checks

### 6.3 Vinyl (Index Abstraction)

#### 6.3.1 Hash Table Operations
- [ ] Test vinyl map insertion
- [ ] Verify vinyl map lookup
- [ ] Test vinyl map deletion
- [ ] Validate vinyl map resize
- [ ] Test linear probing collision resolution
- [ ] Verify probe sequence repair
- [ ] Test hash table load factor
- [ ] Validate hash table tombstone handling

#### 6.3.2 Concurrency
- [ ] Test concurrent vinyl reads
- [ ] Verify vinyl lock-free reads
- [ ] Test vinyl write serialization
- [ ] Validate vinyl memory ordering
- [ ] Test vinyl under high contention
- [ ] Verify vinyl CAS operations
- [ ] Test vinyl memory fences
- [ ] Validate vinyl race condition handling

---

## 7. IPC & Shared Memory

### 7.1 Mcache (Metadata Cache)

#### 7.1.1 Message Passing
- [ ] Test mcache write operation
- [ ] Verify mcache read operation
- [ ] Test mcache sequence number ordering
- [ ] Validate mcache overrun detection
- [ ] Test mcache TOCTOU race condition (`fd_mcache.h:578-605`)
- [ ] Verify mcache wraparound handling
- [ ] Test mcache under high throughput
- [ ] Validate mcache line initialization

#### 7.1.2 Flow Control
- [ ] Test mcache backpressure
- [ ] Verify mcache consumer slow path
- [ ] Test mcache producer blocking
- [ ] Validate mcache flow sequence
- [ ] Test mcache credit-based flow control
- [ ] Verify mcache stall recovery
- [ ] Test mcache under producer/consumer rate mismatch
- [ ] Validate mcache metrics

### 7.2 Dcache (Data Cache)

#### 7.2.1 Chunk Management
- [ ] Test dcache chunk allocation
- [ ] Verify dcache chunk deallocation
- [ ] Test dcache chunk alignment (64-byte)
- [ ] Validate dcache chunk addressing
- [ ] Test dcache chunk wraparound
- [ ] Verify dcache watermark handling
- [ ] Test dcache chunk exhaustion
- [ ] Validate dcache chunk compaction

#### 7.2.2 Data Integrity
- [ ] Test dcache data write
- [ ] Verify dcache data read
- [ ] Test dcache guard region (3968 bytes)
- [ ] Validate dcache bounds checking
- [ ] Test dcache data initialization (not zeroed - potential info leak)
- [ ] Verify dcache MTU enforcement
- [ ] Test dcache data corruption detection
- [ ] Validate dcache magic number checks

### 7.3 Tcache (Tag Cache)

#### 7.3.1 Deduplication
- [ ] Test tcache tag insertion
- [ ] Verify tcache tag lookup
- [ ] Test tcache bloom filter
- [ ] Validate tcache eviction
- [ ] Test tcache under collision
- [ ] Verify tcache reset
- [ ] Test tcache infinite loop risk (`fd_tcache.h:287`)
- [ ] Validate tcache performance

### 7.4 CNC (Command & Control)

#### 7.4.1 Signaling
- [ ] Test CNC signal delivery
- [ ] Verify CNC heartbeat mechanism
- [ ] Test CNC process liveness detection
- [ ] Validate CNC PID reuse handling (`fd_cnc.c:176-200` - race condition)
- [ ] Test CNC lock acquisition
- [ ] Verify CNC lock release
- [ ] Test CNC under process crash
- [ ] Validate CNC signal ordering

---

## 8. Memory Safety & Process Isolation

### 8.1 Sandbox Implementation

#### 8.1.1 Initialization Sequence
- [ ] Test sandbox 14-step initialization order
- [ ] Verify environment variable clearing
- [ ] Test file descriptor validation
- [ ] Validate session keyring replacement
- [ ] Test controlling terminal detachment
- [ ] Verify UID/GID switching
- [ ] Test first user namespace creation
- [ ] Validate namespace unsharing
- [ ] Test namespace creation denial
- [ ] Verify nested user namespace creation
- [ ] Test KEEPCAPS clearing
- [ ] Validate pivot root operation
- [ ] Test Landlock restrictions
- [ ] Verify resource limit setting
- [ ] Test capability dropping
- [ ] Validate no_new_privs bit
- [ ] Test seccomp filter installation

#### 8.1.2 Seccomp-BPF Filters
- [ ] Test seccomp filter per tile (2-5 syscalls)
- [ ] Verify syscall whitelist enforcement
- [ ] Test blocked syscall returns EPERM
- [ ] Validate seccomp filter generation
- [ ] Test seccomp filter arguments
- [ ] Verify seccomp filter installation order
- [ ] Test seccomp filter bypass attempts
- [ ] Validate seccomp metrics

#### 8.1.3 Namespace Isolation
- [ ] Test user namespace isolation
- [ ] Verify PID namespace isolation
- [ ] Test network namespace isolation
- [ ] Validate mount namespace isolation
- [ ] Test IPC namespace isolation
- [ ] Verify UTS namespace isolation
- [ ] Test cgroup namespace isolation
- [ ] Validate namespace escape attempts

### 8.2 Capability Management

#### 8.2.1 Capability Dropping
- [ ] Test all capabilities dropped
- [ ] Verify bounding set cleared
- [ ] Test capability inheritance
- [ ] Validate ambient capabilities cleared
- [ ] Test capability restoration attempts
- [ ] Verify permitted set empty
- [ ] Test effective set empty
- [ ] Validate inheritable set empty

#### 8.2.2 Privilege Separation
- [ ] Test NET tile with CAP_NET_RAW
- [ ] Verify NET tile with CAP_NET_ADMIN
- [ ] Test other tiles without network caps
- [ ] Validate tiles run as unprivileged user
- [ ] Test tile UID/GID isolation
- [ ] Verify tile process tree
- [ ] Test tile restart after crash
- [ ] Validate tile privilege escalation prevention

### 8.3 Memory Management

#### 8.3.1 Workspace Allocator
- [ ] Test workspace allocation
- [ ] Verify workspace alignment
- [ ] Test workspace bounds checking
- [ ] Validate workspace magic numbers
- [ ] Test workspace corruption detection
- [ ] Verify workspace pre-allocation
- [ ] Test workspace exhaustion
- [ ] Validate workspace partitioning

#### 8.3.2 Huge Pages
- [ ] Test huge page allocation (2MB)
- [ ] Verify gigantic page allocation (1GB)
- [ ] Test huge page fallback
- [ ] Validate huge page TLB benefits
- [ ] Test huge page locking
- [ ] Verify huge page permissions
- [ ] Test huge page fragmentation
- [ ] Validate huge page metrics

#### 8.3.3 NUMA Awareness
- [ ] Test NUMA node allocation
- [ ] Verify CPU affinity to NUMA nodes
- [ ] Test cross-NUMA access penalties
- [ ] Validate NUMA memory policy
- [ ] Test NUMA migration
- [ ] Verify NUMA balancing
- [ ] Test NUMA topology detection
- [ ] Validate NUMA metrics

### 8.4 Compiler Protections

#### 8.4.1 Build Hardening
- [ ] Verify PIE (Position Independent Executable) enabled
- [ ] Test ASLR (Address Space Layout Randomization)
- [ ] Verify stack canaries (-fstack-protector-strong)
- [ ] Test stack canary bypass attempts
- [ ] Verify RELRO (Read-Only Relocations) - full
- [ ] Test GOT/PLT modification attempts
- [ ] Verify FORTIFY_SOURCE=2
- [ ] Test buffer overflow detection

#### 8.4.2 Sanitizers (Development Builds)
- [ ] Run with AddressSanitizer (ASan)
- [ ] Run with UndefinedBehaviorSanitizer (UBSan)
- [ ] Run with MemorySanitizer (MSan) if applicable
- [ ] Run with ThreadSanitizer (TSan) for concurrency bugs
- [ ] Test fuzzing with sanitizers enabled
- [ ] Verify sanitizer reports
- [ ] Test sanitizer performance impact
- [ ] Validate sanitizer coverage

---

## 9. Denial of Service Protections

### 9.1 Network Layer DoS

#### 9.1.1 Connection Limits
- [ ] Test maximum concurrent connections (131,072)
- [ ] Verify connection allocation failures
- [ ] Test connection exhaustion attack
- [ ] Validate per-IP connection limits (not implemented - potential gap)
- [ ] Test handshake slot exhaustion
- [ ] Verify retry token rate limiting
- [ ] Test SYN flood mitigation
- [ ] Validate connection aging

#### 9.1.2 Packet Rate Limiting
- [ ] Test packet ingress rate limits
- [ ] Verify packet drop under overload
- [ ] Test packet prioritization
- [ ] Validate XDP packet filtering
- [ ] Test amplification attack prevention
- [ ] Verify minimum packet size enforcement (1200 bytes)
- [ ] Test packet flood scenarios
- [ ] Validate packet queue depths

#### 9.1.3 Resource Exhaustion
- [ ] Test frame pool exhaustion (2500 default)
- [ ] Verify stream pool exhaustion
- [ ] Test inflight packet limits
- [ ] Validate buffer exhaustion handling
- [ ] Test memory exhaustion scenarios
- [ ] Verify CPU exhaustion under load
- [ ] Test file descriptor exhaustion
- [ ] Validate graceful degradation

### 9.2 Compute Budget DoS

#### 9.2.1 Transaction Limits
- [ ] Test per-transaction CU limit (1.4M)
- [ ] Verify per-block CU limit (100M)
- [ ] Test per-account write limit (12M)
- [ ] Validate CU overflow attack
- [ ] Test transaction with excessive compute
- [ ] Verify CU metering bypass attempts
- [ ] Test compute budget program exploitation
- [ ] Validate priority fee manipulation

#### 9.2.2 Account Data Limits
- [ ] Test account data growth limit per transaction
- [ ] Verify total account data allocation limit (20MiB/txn)
- [ ] Test maximum account data size (10MiB)
- [ ] Validate account reallocation attacks
- [ ] Test account data DoS scenarios
- [ ] Verify account rent exemption
- [ ] Test account data initialization costs
- [ ] Validate account data zeroing

### 9.3 Consensus Layer DoS

#### 9.3.1 Vote Processing
- [ ] Test vote flood scenarios
- [ ] Verify vote rate limiting
- [ ] Test conflicting vote handling
- [ ] Validate vote deduplication
- [ ] Test vote signature verification load
- [ ] Verify vote propagation limits
- [ ] Test vote storage exhaustion
- [ ] Validate vote expiration

#### 9.3.2 Fork Bombing
- [ ] Test fork creation limits
- [ ] Verify Ghost pool capacity
- [ ] Test fork depth limits
- [ ] Validate fork pruning effectiveness
- [ ] Test intentional fork bombing attack
- [ ] Verify fork resolution under attack
- [ ] Test fork storage exhaustion
- [ ] Validate fork memory limits

#### 9.3.3 Shred Flooding
- [ ] Test shred ingress rate
- [ ] Verify shred deduplication
- [ ] Test invalid shred flooding
- [ ] Validate FEC set limits
- [ ] Test shred storage exhaustion
- [ ] Verify shred expiration
- [ ] Test shred verification load
- [ ] Validate shred reassembly limits

---

## 10. Configuration & Deployment

### 10.1 Configuration Validation

#### 10.1.1 TOML Parsing
- [ ] Test TOML configuration parsing
- [ ] Verify invalid TOML rejection
- [ ] Test missing required fields
- [ ] Validate default value application
- [ ] Test configuration value ranges
- [ ] Verify configuration type checking
- [ ] Test malformed TOML handling
- [ ] Validate configuration file permissions

#### 10.1.2 Network Configuration
- [ ] Test port configuration (8001, 8003, 9001, 9007)
- [ ] Verify bind address configuration
- [ ] Test interface selection
- [ ] Validate IP address parsing
- [ ] Test port conflict detection
- [ ] Verify privileged port binding
- [ ] Test dynamic port allocation
- [ ] Validate network namespace configuration

#### 10.1.3 Resource Configuration
- [ ] Test huge page configuration
- [ ] Verify CPU affinity configuration
- [ ] Test memory limit configuration
- [ ] Validate workspace size configuration
- [ ] Test connection limit configuration
- [ ] Verify thread count configuration
- [ ] Test file descriptor limit configuration
- [ ] Validate tile configuration

### 10.2 Key Management

#### 10.2.1 Validator Identity
- [ ] Test identity keypair loading
- [ ] Verify identity key permissions (0600)
- [ ] Test identity key validation
- [ ] Validate identity key rotation
- [ ] Test identity key backup/recovery
- [ ] Verify identity key in configuration
- [ ] Test missing identity key handling
- [ ] Validate identity key format (JSON)

#### 10.2.2 Vote Account
- [ ] Test vote keypair loading
- [ ] Verify vote key permissions
- [ ] Test vote key validation
- [ ] Validate vote account creation
- [ ] Test vote account delegation
- [ ] Verify vote key rotation
- [ ] Test vote account withdrawal
- [ ] Validate vote account commission

#### 10.2.3 Key Security
- [ ] Test key encryption at rest
- [ ] Verify key memory protection
- [ ] Test key secure deletion
- [ ] Validate key access logging
- [ ] Test unauthorized key access attempts
- [ ] Verify key derivation (if applicable)
- [ ] Test hardware security module integration (if applicable)
- [ ] Validate key backup procedures

### 10.3 Monitoring & Metrics

#### 10.3.1 Prometheus Metrics
- [ ] Test metrics endpoint (port 7999)
- [ ] Verify metrics format (Prometheus)
- [ ] Test metrics authentication
- [ ] Validate tile-specific metrics
- [ ] Test link-specific metrics
- [ ] Verify performance counters
- [ ] Test custom metrics
- [ ] Validate metrics cardinality

#### 10.3.2 Health Checks
- [ ] Test tile health monitoring
- [ ] Verify process liveness checks
- [ ] Test heartbeat mechanism
- [ ] Validate tile restart on failure
- [ ] Test cascading failure detection
- [ ] Verify automatic recovery
- [ ] Test manual restart procedures
- [ ] Validate health check metrics

#### 10.3.3 Logging
- [ ] Test log level configuration
- [ ] Verify log output formatting
- [ ] Test log rotation
- [ ] Validate log retention
- [ ] Test structured logging
- [ ] Verify log correlation
- [ ] Test sensitive data redaction in logs
- [ ] Validate log monitoring integration

---

## 11. Agave Runtime Integration

### 11.1 Frankendancer IPC

#### 11.1.1 Shared Memory Communication
- [ ] Test Firedancer → Agave transaction passing
- [ ] Verify Agave → Firedancer result passing
- [ ] Test shared memory permissions
- [ ] Validate memory synchronization
- [ ] Test shared memory corruption detection
- [ ] Verify shared memory layout compatibility
- [ ] Test shared memory exhaustion
- [ ] Validate shared memory cleanup

#### 11.1.2 Funk Integration
- [ ] Test Funk transactional semantics with Agave
- [ ] Verify account state consistency
- [ ] Test transaction commit coordination
- [ ] Validate rollback handling
- [ ] Test concurrent access from Agave
- [ ] Verify Funk record format compatibility
- [ ] Test Funk corruption recovery
- [ ] Validate Funk performance under load

#### 11.1.3 Process Lifecycle
- [ ] Test Agave subprocess spawning
- [ ] Verify Agave subprocess configuration
- [ ] Test Agave subprocess monitoring
- [ ] Validate Agave subprocess restart
- [ ] Test Agave subprocess crash handling
- [ ] Verify Agave subprocess termination
- [ ] Test Agave subprocess resource limits
- [ ] Validate Agave subprocess cleanup

### 11.2 Agave Runtime Security

#### 11.2.1 sBPF VM (Agave)
- [ ] Test Agave sBPF VM independently
- [ ] Verify Agave syscall implementations
- [ ] Test Agave VM instruction validation
- [ ] Validate Agave memory access controls
- [ ] Test Agave compute unit metering
- [ ] Verify Agave CPI security
- [ ] Test Agave program loading
- [ ] Validate Agave execution determinism

#### 11.2.2 Runtime Components
- [ ] Test Agave bank execution
- [ ] Verify Agave account locking
- [ ] Test Agave transaction processing
- [ ] Validate Agave PoH integration
- [ ] Test Agave block production
- [ ] Verify Agave replay validation
- [ ] Test Agave snapshot generation
- [ ] Validate Agave state synchronization

#### 11.2.3 Consensus (Agave)
- [ ] Test Agave Tower BFT implementation
- [ ] Verify Agave voting logic
- [ ] Test Agave fork choice
- [ ] Validate Agave lockout enforcement
- [ ] Test Agave optimistic confirmation
- [ ] Verify Agave vote replay
- [ ] Test Agave consensus under Byzantine conditions
- [ ] Validate Agave finality guarantees

### 11.3 Compatibility Testing

#### 11.3.1 Transaction Compatibility
- [ ] Test transaction format compatibility
- [ ] Verify signature compatibility
- [ ] Test account format compatibility
- [ ] Validate instruction format compatibility
- [ ] Test versioned transaction support
- [ ] Verify address lookup table support
- [ ] Test durable nonce compatibility
- [ ] Validate fee payer compatibility

#### 11.3.2 Protocol Compatibility
- [ ] Test feature gate compatibility
- [ ] Verify epoch boundary handling
- [ ] Test hard fork compatibility
- [ ] Validate protocol version negotiation
- [ ] Test deprecated feature handling
- [ ] Verify feature activation
- [ ] Test feature deactivation
- [ ] Validate protocol upgrade paths

---

## 12. Supply Chain & Build Security

### 12.1 Build System

#### 12.1.1 Source Verification
- [ ] Verify Git repository integrity
- [ ] Test submodule integrity (Agave)
- [ ] Validate commit signature verification
- [ ] Test reproducible builds
- [ ] Verify build artifact checksums
- [ ] Test source tarball verification
- [ ] Validate dependency pinning
- [ ] Test supply chain attack mitigations

#### 12.1.2 Compiler Toolchain
- [ ] Test build with GCC
- [ ] Verify build with Clang
- [ ] Test cross-compilation
- [ ] Validate compiler version requirements
- [ ] Test compiler flag validation
- [ ] Verify optimization level safety
- [ ] Test linker security flags
- [ ] Validate toolchain integrity

#### 12.1.3 Dependencies
- [ ] Audit C library dependencies
- [ ] Verify Rust crate dependencies (Agave)
- [ ] Test vendored dependencies
- [ ] Validate dependency licenses
- [ ] Test dependency update procedures
- [ ] Verify dependency vulnerability scanning
- [ ] Test minimal dependency principle
- [ ] Validate dependency integrity checks

### 12.2 Runtime Environment

#### 12.2.1 Operating System
- [ ] Test on Ubuntu 20.04+
- [ ] Verify kernel version requirements (5.13+ for Landlock)
- [ ] Test with different kernel configurations
- [ ] Validate kernel module requirements
- [ ] Test with various init systems
- [ ] Verify SELinux compatibility (if applicable)
- [ ] Test AppArmor compatibility (if applicable)
- [ ] Validate system call availability

#### 12.2.2 Hardware Requirements
- [ ] Test on x86_64 architecture
- [ ] Verify AVX-512 instruction support
- [ ] Test on systems without AVX-512 (fallback)
- [ ] Validate AF_XDP NIC support
- [ ] Test huge page support
- [ ] Verify NUMA topology handling
- [ ] Test on various CPU vendors (Intel, AMD)
- [ ] Validate minimum CPU/memory requirements

#### 12.2.3 Network Infrastructure
- [ ] Test in datacenter environment
- [ ] Verify cloud environment compatibility
- [ ] Test with various network topologies
- [ ] Validate NAT traversal
- [ ] Test with firewalls
- [ ] Verify load balancer compatibility
- [ ] Test in IPv4/IPv6 dual-stack
- [ ] Validate VLAN support

### 12.3 Deployment Security

#### 12.3.1 Installation
- [ ] Test clean installation from source
- [ ] Verify package installation (if available)
- [ ] Test upgrade procedures
- [ ] Validate rollback procedures
- [ ] Test multi-node deployment
- [ ] Verify configuration migration
- [ ] Test installation automation
- [ ] Validate installation integrity checks

#### 12.3.2 Updates
- [ ] Test in-place updates
- [ ] Verify update verification (signatures)
- [ ] Test update rollback
- [ ] Validate update coordination
- [ ] Test zero-downtime updates
- [ ] Verify update notifications
- [ ] Test emergency updates
- [ ] Validate update compatibility

#### 12.3.3 Operational Security
- [ ] Test firewall configuration
- [ ] Verify port exposure (public vs private)
- [ ] Test access control mechanisms
- [ ] Validate audit logging
- [ ] Test intrusion detection integration
- [ ] Verify security monitoring
- [ ] Test incident response procedures
- [ ] Validate backup/recovery procedures

---

## Testing Methodology

### Static Analysis
- [ ] Perform manual code review of critical paths
- [ ] Run Clang Static Analyzer
- [ ] Run Coverity (if available)
- [ ] Execute custom static analysis scripts
- [ ] Review compiler warnings
- [ ] Analyze call graphs for complexity
- [ ] Check for FIXME/TODO markers indicating incomplete security checks
- [ ] Validate coding standards compliance

### Dynamic Analysis
- [ ] Execute unit tests with coverage analysis
- [ ] Run integration tests
- [ ] Perform fuzz testing with AFL/libFuzzer
- [ ] Execute stress tests
- [ ] Run long-duration stability tests
- [ ] Test with Valgrind for memory errors
- [ ] Execute thread/concurrency tests
- [ ] Validate under adversarial conditions

### Runtime Testing
- [ ] Deploy to local fddev test node
- [ ] Test with mainnet-beta transactions
- [ ] Execute attack scenario playbooks
- [ ] Monitor resource consumption
- [ ] Analyze performance under load
- [ ] Test failure recovery
- [ ] Validate metrics accuracy
- [ ] Execute chaos engineering tests

### Compliance Testing
- [ ] Verify Solana protocol compliance
- [ ] Test consensus compatibility with Agave validators
- [ ] Validate RPC API compatibility
- [ ] Test gossip protocol compatibility
- [ ] Verify transaction format compliance
- [ ] Test against Solana test suite
- [ ] Validate feature gate behavior
- [ ] Execute conformance tests

---

## Risk Assessment Criteria

Each identified issue should be assessed using the following criteria:

### Severity Levels
- **Critical**: Remote code execution, consensus violation, fund loss
- **High**: Privilege escalation, DoS, significant security bypass
- **Medium**: Information disclosure, resource exhaustion, degraded security
- **Low**: Minor security weaknesses, theoretical vulnerabilities

### Exploitability
- **Easy**: Exploitable by unskilled attacker with public tools
- **Medium**: Requires specialized knowledge or tools
- **Hard**: Requires deep expertise and significant resources
- **Very Hard**: Theoretical or requires physical access

### Impact Scope
- **Network-wide**: Affects entire Solana network
- **Validator**: Affects single validator operation
- **Isolated**: Affects single component/tile
- **Minimal**: Limited or theoretical impact

---

## Known Issues Reference

The following issues have been documented in prior security analysis and should be explicitly validated:

### Critical Priority
1. sBPF VM binary search OOB (`fd_vm_private.h:296`)
2. Compute unit overflow (`fd_pack.c`)
3. CMR overwriting without validation (`fd_reasm.c:186`)
4. Equivocation pool exhaustion (`fd_eqvoc.c:113`)

### High Priority
5. CPI account length race condition (`fd_vm_syscall_cpi_common.c:163`)
6. Bundle signature limit of 4 (`fd_dedup_tile.c:194`)
7. Missing gossip double-vote check (`fd_gossip.c`)
8. QUIC retry IV reuse risk (`fd_quic_retry.h:86`)

### Medium Priority
9. Mcache TOCTOU race (`fd_mcache.h:578`)
10. Ghost pool exhaustion (`fd_ghost.c:299`)
11. CNC PID reuse vulnerability (`fd_cnc.c:176`)
12. PoH timing oracle (`fd_poh.c`)
13. Funk HashDoS on 32-bit platforms (`fd_funk_base.h:203`)

---

## Completion Tracking

**Total Checklist Items**: 600+
**Items Completed**: [ ] 0
**Critical Items Completed**: [ ] 0/4
**High Items Completed**: [ ] 0/4
**Medium Items Completed**: [ ] 0/5

**Assessment Start Date**: _____________
**Assessment End Date**: _____________
**Lead Assessor**: _____________
**Review Status**: [ ] In Progress [ ] Complete [ ] Verified

---

## References

- Firedancer Documentation: `./book/`
- Security Research: `./SR/*.md`
- Source Code: `./src/`
- Agave Documentation: `./agave/docs/`
- Configuration: `./src/app/fdctl/config/default.toml`
- Critical Findings: `./SR/CRITICAL_FINDINGS_SUMMARY.md`

---

**END OF CHECKLIST**
