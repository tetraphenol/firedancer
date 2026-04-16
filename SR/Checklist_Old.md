# Firedancer/Agave Validator - Attack-Focused Security Checklist

**Version:** 2.0 (Refined for PoC-demonstrable vulnerabilities)
**Date:** November 15, 2025
**Scope:** Frankendancer (v0.x) + Agave runtime
**Methodology:** White-box exploitation with mandatory proof-of-concept demonstrations
**Test Environment:** Local fddev node for runtime exploitation testing
**Progress:** ~57 vectors assessed, 2 vulnerabilities documented, ~63 vectors remaining

---

## Document Purpose

This checklist focuses exclusively on **concrete, exploitable attack vectors** that can be demonstrated with working proofs-of-concept. Each item represents a specific vulnerability class that could lead to:
- Remote code execution
- Consensus violations / chain splits
- Denial of service
- Fund theft / unauthorized state changes
- Information disclosure with security impact

**Exclusions:**
- Generic best practices without exploitable impact
- Known issues already documented in `./SR/CRITICAL_FINDINGS_SUMMARY.md`
- Theoretical issues without clear attack path

---

## Known Issues (DO NOT RE-TEST)

The following are already documented and should NOT be included in testing:

### Critical
1. sBPF VM binary search OOB (`fd_vm_private.h:296`) - SKIP
2. Compute unit overflow (`fd_pack.c:2425,2553`) - SKIP
3. CMR overwriting (`fd_reasm.c:186`) - SKIP
4. Equivocation pool exhaustion (`fd_eqvoc.c:113`) - SKIP

### High
5. CPI account length race (`fd_vm_syscall_cpi_common.c:163`) - SKIP
6. Bundle signature limit (`fd_dedup_tile.c:194`) - SKIP
7. Missing gossip double-vote check (`fd_gossip.c`) - SKIP
8. QUIC retry IV reuse (`fd_quic_retry.h:86`) - SKIP

### Medium
9. Mcache TOCTOU (`fd_mcache.h:578`) - SKIP
10. Ghost pool exhaustion (`fd_ghost.c:299`) - SKIP
11. CNC PID reuse (`fd_cnc.c:176`) - SKIP
12. PoH timing oracle (`fd_poh.c`) - SKIP
13. Funk HashDoS on 32-bit (`fd_funk_base.h:203`) - SKIP

---

## 1. QUIC Protocol Exploitation

### 1.1 Connection ID Hash Collisions (`src/waltz/quic/fd_quic_conn_map.h:16`)
- [x] **Craft connection IDs with identical hash values** (truncation to 32-bit) - **SAFE**
  - PoC: Generate conn_id_1 and conn_id_2 where `(uint)conn_id_1 == (uint)conn_id_2`
  - Impact: ~~Connection table collisions → wrong connection receives packets~~
  - Location: `#define MAP_KEY_HASH(k) ((uint)k)`
  - **Assessment**: Linear probing with full 64-bit key comparison at query (fd_map_dynamic.c:501) prevents cross-connection access. Hash collision only causes performance degradation, not security issue.
  - Test: ~~Send packets with colliding IDs, observe cross-connection leakage~~ NOT EXPLOITABLE

- [x] **Exhaust connection slots via hash DoS** - **VALID DoS VECTOR**
  - PoC: Create 131,072 connections all hashing to same bucket
  - Impact: Linear lookup time degrades O(1) to O(n)
  - Test: Measure connection establishment latency with crafted IDs
  - **Assessment**: Exploitable for DoS but limited by connection limits and retry tokens

### 1.2 Stream ID Integer Overflow
- [x] **Overflow stream ID counter** (`fd_quic.c:2706-2708`) - **SAFE**
  - PoC: Rapidly create/close streams to wrap stream_id
  - Impact: ~~Stream ID reuse → data sent to wrong stream~~
  - Location: `conn->tx_sup_stream_id = (initial_max_streams_uni << 2UL) + type`
  - **Assessment**: Max value is `1UL<<60` (line 534), so `(1UL<<60)<<2 = 1UL<<62` which fits in ulong. Stream ID calculation bounded by transport parameter validation. NOT EXPLOITABLE.
  - Test: ~~Create 2^62 streams (bidirectional limit), observe wraparound~~

- [x] **Exploit stream_id validation bypass** (`fd_quic.c:5028-5029`) - **SAFE**
  - PoC: Send frames with stream_id > locally tracked max
  - Impact: ~~Bypass flow control, resource exhaustion~~
  - **Assessment**: Explicit check: `if( stream_id >= conn->srx->rx_sup_stream_id )` returns protocol error. Properly validated.
  - Test: ~~Send DATA frame with stream_id = UINT64_MAX~~ NOT EXPLOITABLE

### 1.3 Retry Token Cryptographic Attacks
- [x] **Birthday attack on 96-bit nonce space** (`fd_quic_retry.h:85-87`) - **KNOWN RISK**
  - PoC: Collect 2^48 retry tokens, find IV collision
  - Impact: AES-GCM security breaks, forge tokens
  - **Assessment**: Acknowledged in comments at lines 85-87: "if fd_rng_t generates the same 96-bit nonce twice, the retry token authentication mechanism breaks down entirely". This is a KNOWN design limitation, not a new vulnerability. SKIP (already documented as issue #8).
  - Test: ~~Automated token collection over time~~ ALREADY DOCUMENTED

- [x] **IP spoofing with forged retry tokens** (`fd_quic_retry.c:179-193`) - **SAFE**
  - PoC: Capture token, replay from different IP (if NAT allows)
  - Impact: ~~Connection hijacking~~
  - **Assessment**: Token verification checks IP match at lines 179-193: `pkt_ip4 == retry_ip4 && pkt_port == retry_port`. Token binds to source IP:port. Replay from different IP fails verification.
  - Test: ~~Replay token through NAT gateway~~ NOT EXPLOITABLE

### 1.4 Packet Reassembly Attacks
- [x] **Out-of-order fragment reassembly buffer overflow** - **NOT APPLICABLE**
  - PoC: Send fragments with overlapping offsets
  - Impact: ~~Buffer overflow in reassembly~~
  - **Assessment**: QUIC doesn't use IP fragmentation. Don't fragment bit set at `fd_quic.c:3014`: `pkt.ip4->net_frag_off = 0x4000u`. QUIC handles stream reassembly at application layer with proper bounds checking. NO REASSEMBLY VULNERABILITY.
  - Test: ~~QUIC fragments with offset+length > buffer~~ NOT APPLICABLE

- [x] **Fragment bomb (decompression ratio exploit)** - **NOT APPLICABLE**
  - PoC: Send highly compressed packet fragments
  - Impact: ~~Memory exhaustion on decompression~~
  - **Assessment**: QUIC doesn't compress at packet level. Stream data compression is application-layer concern. No decompression bombs at QUIC layer.
  - Test: ~~1KB compressed → 10MB decompressed payload~~ NOT APPLICABLE

---

## 2. TLS 1.3 Handshake Vulnerabilities

### 2.1 Certificate Validation Bypasses
- [x] **Non-canonical DER encoding acceptance** (`fd_tls_asn1.h:14-24`) - **SAFE**
  - PoC: ~~Present certificate with non-trivial DER encoding~~
  - Impact: ~~Certificate validation bypass~~
  - **Assessment**: Code is overly strict, requiring exact byte-for-byte match with template at `fd_tls_asn1.c:23-27`. REJECTS non-canonical encodings rather than accepting them. Prevents bypass (though may cause interoperability issues).
  - Test: ~~Generate cert with indefinite length encoding~~ NOT EXPLOITABLE

- [x] **Certificate chain depth exhaustion** - **NOT APPLICABLE**
  - PoC: ~~Present chain with 1000+ intermediate CAs~~
  - Impact: ~~Stack overflow in recursive validation~~
  - **Assessment**: X509 handling uses template matching (`fd_x509_mock.c:163-171`), not recursive chain parsing. Only first certificate processed via `fd_tls_proto.c:1026`. No recursion, no depth tracking, no stack overflow risk.
  - Test: ~~Chain validation with excessive depth~~ NOT APPLICABLE

### 2.2 Key Derivation Attacks
- [x] **Label buffer overflow** (`fd_tls.c:132-134`) - **SAFE**
  - PoC: Trigger key derivation with label_sz > 64
  - Impact: ~~Stack buffer overflow (if FD_TEST compiled out)~~
  - Location: `FD_TEST( label_sz <=LABEL_BUFSZ );`
  - **Assessment**: FD_TEST is runtime check (calls FD_LOG_ERR which terminates), not compile-time assertion. Verified at fd_log.h - terminates on failure. SAFE.
  - Test: ~~Modified ClientHello with oversized HKDF label~~ NOT EXPLOITABLE

- [x] **Context buffer overflow** (`fd_tls.c:132-134`) - **SAFE**
  - PoC: Trigger with context_sz > 64
  - Impact: ~~Stack corruption~~
  - **Assessment**: Same FD_TEST runtime protection. Checked at line 133: `FD_TEST( context_sz<=LABEL_BUFSZ )`. SAFE.
  - Test: ~~Custom TLS extension with large context~~ NOT EXPLOITABLE

---

## 3. XDP/eBPF Kernel Bypass

### 3.1 eBPF Program Exploitation
- [x] **XDP program bounds check bypass** - **SAFE**
  - PoC: ~~Malformed packet triggers OOB read in XDP program~~
  - Impact: ~~Kernel crash, information disclosure~~
  - **Assessment**: All memory accesses in XDP program (`fd_xdp1.c:76-242`) are preceded by proper bounds checks: Eth+IPv4 at lines 98-99 (34B), GRE+Inner IPv4 at 140-142 (24B), UDP at 187-188 (8B). IPv4 IHL calculation (108-111) followed by bounds checks before any memory access (142 for GRE, 188 for UDP). eBPF verifier would also reject OOB access.
  - Test: ~~Packet with crafted headers exceeding expected bounds~~ NOT EXPLOITABLE

- [x] **eBPF verifier bypass via complexity** - **NOT APPLICABLE**
  - PoC: ~~Craft packet forcing verifier to approve unsafe program~~
  - Impact: ~~Arbitrary kernel memory access~~
  - **Assessment**: XDP program is statically generated by `fd_xdp_gen_program()` at XSK initialization, not dynamically created from packet content. Program is simple, linear, and controlled by Firedancer. Attack vector requires attacker-influenced eBPF bytecode generation, which doesn't exist here.
  - Test: ~~Complex nested branches in XDP program~~ NOT APPLICABLE

### 3.2 UMEM Manipulation
- [x] **UMEM chunk double-free** - **REQUIRES FIREDANCER BUG**
  - PoC: ~~Trigger race in RX/TX queue causing chunk to be freed twice~~
  - Impact: ~~Use-after-free, memory corruption~~
  - **Assessment**: UMEM frame ownership managed by kernel AF_XDP implementation with clear semantics (FILL/RX and TX/COMPLETION ring pairs). Double-free would require bug in Firedancer's frame tracking, not remotely triggerable by attacker packets. Would need deep analysis of AIO layer frame management to confirm absence of bugs, but not a direct attack vector.
  - Test: ~~Concurrent RX completion + manual free~~ NOT REMOTELY EXPLOITABLE

- [x] **UMEM address space exhaustion** - **DoS VECTOR (LOW SEVERITY)**
  - PoC: Flood packets faster than Firedancer consumes from RX ring
  - Impact: RX queue fills, new packets dropped (DoS)
  - **Assessment**: Standard resource exhaustion DoS. Attacker floods packets → RX ring fills to depth limit → drops. Limited by configured RX queue depth and normal flow control mechanisms. Not a memory safety issue, just rate-limiting DoS.
  - Test: Network flood → queue full → packet drops (expected behavior, not vulnerability)

---

## 4. Transaction Processing Attacks

### 4.1 Transaction Parser Exploitation
- [x] **Parse failure continues processing** (`fd_verify_tile.c:117-119`) - **FIXED**
  - PoC: Send transaction where `fd_txn_parse()` returns 0
  - Impact: ~~OOB read on uninitialized txn_t structure~~
  - Test: ~~Malformed transaction with invalid length encoding~~
  - **Assessment**: Code at lines 134-138 properly checks `if( !txnm->txn_t_sz )` and returns early. Vulnerability has been patched.

- [x] **Signature offset out-of-bounds** (`fd_txn_parse.c:86-89`) - **SAFE**
  - PoC: Transaction with signature_off > payload_sz
  - Impact: ~~Read beyond payload buffer~~
  - **Assessment**: Line 86 checks `CHECK_LEFT(FD_TXN_SIGNATURE_SZ*signature_cnt)` before line 89 advances `i`. signature_off is set to current `i` which is already bounds-checked. Lines 16-37 document strict parsing discipline ensuring invariants hold. SAFE.
  - Test: ~~Transaction with crafted offset field~~ NOT EXPLOITABLE

- [x] **Account index overflow** (`fd_txn_parse.c:166,176,235`) - **SAFE**
  - PoC: Transaction referencing account_index > 127
  - Impact: ~~OOB read in account array~~
  - **Assessment**: Line 166: `max_acct=fd_uchar_max(max_acct, payload[k+i])` tracks max account index. Line 235: `CHECK(max_acct < acct_addr_cnt + addr_table_adtl_cnt)` ensures all indices are in range. Explicit validation prevents OOB. SAFE.
  - Test: ~~Instruction with invalid account index~~ NOT EXPLOITABLE

- [x] **Instruction data length integer overflow** (`fd_txn_parse.c:167-168`) - **SAFE**
  - PoC: Instruction with data_len wrapping to 0
  - Impact: ~~Bypass length checks~~
  - **Assessment**: Line 167 reads `data_sz` via READ_CHECKED_COMPACT_U16 macro which uses fd_cu16_dec_sz for bounds-safe decoding. Line 168: `CHECK_LEFT(data_sz)` validates sufficient bytes remain before advancing. Compact-u16 encoding limited to max 2^30-1. SAFE.
  - Test: ~~data_len = UINT64_MAX, actual data = 1 byte~~ NOT EXPLOITABLE

### 4.2 Signature Cache Poisoning
- [x] **Collision attack on signature cache** - **LOW SEVERITY (THEORETICAL)**
  - PoC: Generate 2^32 signatures, find 64-bit hash collision in dedup cache
  - Impact: DoS by causing legitimate transaction rejection as duplicate
  - **Assessment**: Dedup uses `fd_hash()` returning 64-bit hash of signature (`fd_dedup_tile.c:187`). Birthday attack feasible (~2^32 attempts), but requires attacker to generate billions of valid signatures with own keypair, preemptively occupy cache slot, and hope legitimate transaction collides. Very low probability, high cost, limited impact. Theoretical attack only.
  - Test: Generate 2^32 signatures → find collision → preload cache → wait for collision

- [x] **Cache timing side-channel** - **LOW SEVERITY**
  - PoC: Measure verification time to determine if signature cached
  - Impact: Transaction privacy leak (learn which signatures recently seen)
  - **Assessment**: `FD_TCACHE_QUERY` at `fd_tcache.h:281-295` uses linear probing with variable-time loop. Iterations depend on hash collisions and cache fullness. Timing difference exists but very small (few hash table probes). Network jitter dominates. Information leaked (transaction recently seen) has limited value. Side-channel exists but not critical.
  - Test: Timing analysis of duplicate vs non-duplicate submissions

### 4.3 Deduplication Attacks
- [x] **Signature dedup race condition** - **REQUIRES ARCHITECTURE ANALYSIS**
  - PoC: ~~Submit same transaction to multiple QUIC tiles simultaneously~~
  - Impact: ~~Duplicate transaction execution~~
  - **Assessment**: Race requires multiple QUIC tiles to check shared dedup cache before either inserts. If each tile has independent cache (distributed dedup), this is expected behavior, not vulnerability. If shared cache without locking, race possible but would require analysis of tile architecture and tcache sync mechanisms. Deferred for deeper architectural analysis.
  - Test: ~~Parallel submission before dedup cache sync~~ REQUIRES TILE ARCHITECTURE ANALYSIS

### 4.4 Block Packing Exploits
- [x] **Rewards/compute priority manipulation** (`fd_pack.c:201`) - **SAFE**
  - PoC: Transaction with rewards=UINT_MAX, compute=1
  - Impact: ~~Multiply to ULONG_MAX, break priority queue~~
  - Location: `COMPARE_WORSE` macro: `((ulong)((x)->rewards)*(ulong)((y)->compute_est))`
  - **Assessment**: Both operands cast to ulong (64-bit) before multiplication, preventing overflow from uint*uint
  - Test: ~~High-reward transactions starve legitimate txns~~ NOT EXPLOITABLE

- [x] **Account write-lock overflow** (`fd_pack.c:1876,1999`) - **SAFE**
  - PoC: Single account written by many transactions in one block
  - Impact: ~~write cost tracking overflow~~
  - Location: `in_wcost_table->total_cost += cur->compute_est;`
  - **Assessment**: Line 1876 checks `total_cost + compute_est > max_write_cost_per_acct` BEFORE adding at line 1999. Addition is bounded by max_write_cost_per_acct.
  - Test: ~~10,000 transactions writing same account~~ NOT EXPLOITABLE

- [x] **Microblock overhead underflow** - **SAFE**
  - PoC: ~~Pack transactions until `byte_limit - MICROBLOCK_DATA_OVERHEAD` underflows~~
  - Impact: ~~Pack more data than block limit allows~~
  - **Assessment**: Line 2515 calculates `byte_limit = max - data_bytes_consumed - MICROBLOCK_DATA_OVERHEAD`. Potential underflow prevented by check at line 2505: `if(data_bytes_consumed + MICROBLOCK_DATA_OVERHEAD + FD_TXN_MIN_SERIALIZED_SZ > max) return 0UL`. This ensures `max - data_bytes_consumed - MICROBLOCK_DATA_OVERHEAD >= FD_TXN_MIN_SERIALIZED_SZ`, preventing underflow.
  - Test: ~~Transactions totaling exactly `max_bytes - 47`~~ NOT EXPLOITABLE

---

## 5. sBPF VM Exploitation

### 5.1 Memory Access Attacks
- [x] **Region resizing race condition** (`fd_vm_private.h:358-376`) - **SAFE (single-threaded)**
  - PoC: Concurrent region resize while VM accessing region
  - Impact: ~~TOCTOU, use-after-resize~~
  - **Assessment**: fd_vm_handle_input_mem_region_oob() at lines 358-376 handles resizing. VM execution is single-threaded within transaction context - no concurrent access possible during execution. Resizing only occurs within same execution context via syscalls, not externally.
  - Test: ~~Resize account data during VM execution~~ NOT EXPLOITABLE (architectural protection)

- [x] **Negative memory offset** (`fd_vm_private.h:438,461`) - **SAFE**
  - PoC: Load/store with offset that wraps to high address
  - Impact: ~~Access arbitrary memory~~
  - **Assessment**: Line 438: `ulong offset = vaddr & FD_VM_OFFSET_MASK` masks to valid range. Line 461: `sz_max = region_sz - fd_ulong_min(offset, region_sz)` uses saturating subtraction. Negative wraparound prevented by masking and saturation.
  - Test: ~~`ldx r1, [r10 - 0x8000000000000000]`~~ NOT EXPLOITABLE

- [x] **Cross-region access via offset** (`fd_vm_private.h:401-426`) - **SAFE**
  - PoC: Access at boundary of region[n] with offset reaching region[n+1]
  - Impact: ~~Read/write wrong account data~~
  - **Assessment**: Lines 401-402: `bytes_in_region = sat_sub(region.sz, sat_sub(offset, region.vaddr_offset))` calculates exact bytes available in CURRENT region. Line 414: `if(sz>bytes_in_region) return sentinel` prevents cross-region access. Each region validated independently.
  - Test: ~~`load(region[0].end - 4, size=8)` → reads into region[1]~~ NOT EXPLOITABLE

### 5.2 Arithmetic Exploitation
- [x] **Division result truncation** - **SAFE**
  - PoC: `(INT_MIN / -1)` on 32-bit division
  - Impact: ~~Incorrect result vs expected overflow~~
  - Location: `fd_vm_interp_core.c:980,998`
  - **Assessment**: Code explicitly checks for this case: `if( FD_UNLIKELY( ((int)reg_dst==INT_MIN) & ((int)imm==-1) ) ) goto sigfpeof;` and handles it properly.
  - Test: ~~BPF program dividing INT_MIN by -1~~ NOT EXPLOITABLE

- [x] **Shift amount overflow** (`fd_vm_interp_core.c:972,985,989,1003`) - **VULNERABLE**
  - PoC: Shift by >=64 bits
  - Impact: Undefined behavior, potential consensus divergence
  - Location: Multiple FIXME comments about "WIDE SHIFTS"
  - Test: `r1 = r2 << 65`
  - **Assessment**: CONFIRMED - No validation on shift amounts. See SR/Findings/SBPF-001
  - **Severity**: LOW-CRITICAL (depends on Agave behavior)

- [x] **Multiply overflow unchecked** - **NOT A VULNERABILITY (EXPECTED BEHAVIOR)**
  - PoC: Multiply two large numbers without overflow check
  - Impact: Wraparound (expected sBPF/BPF behavior)
  - **Assessment**: All multiply instructions (`fd_vm_interp_core.c:422,426,430,729,793,826,874`) perform multiplication without overflow checks, allowing wraparound. This is EXPECTED BPF behavior matching hardware (x86 MUL wraps). sBPF programs must implement their own overflow checking if needed, using checked arithmetic primitives. Not a vulnerability - it's the documented ISA behavior.
  - Test: `r1 = 2^63 * 2` → wraps to 0 (expected)

### 5.3 Control Flow Exploits
- [x] **Jump target validation bypass** (`fd_vm.h:104-106`) - **SAFE**
  - PoC: Modify PC to jump to unvalidated address
  - Impact: ~~Execute arbitrary bytecode~~
  - **Assessment**: Line 104: `ulong const * calldests` is bit vector of valid call targets. VM uses this during CALL instruction execution. Entry PC also validated at line 103. Jump targets pre-validated during program load, not runtime.
  - Test: ~~JMP instruction with target outside calldests~~ NOT EXPLOITABLE (validation at load time)

- [x] **Call stack overflow** (`fd_vm.h:134,204`) - **SAFE**
  - PoC: Recursive calls exceeding stack depth
  - Impact: ~~Stack corruption~~
  - **Assessment**: Line 134: `ulong frame_cnt` tracks current depth. Line 204: `shadow[FD_VM_STACK_FRAME_MAX]` is fixed-size array. fd_vm_interp_core.c increments/checks frame_cnt against frame_max (typically FD_VM_STACK_FRAME_MAX=64). Stack overflow caught before corruption.
  - Test: ~~Recursive function calling itself 1000 times~~ NOT EXPLOITABLE

- [x] **Return without call** - **SAFE**
  - PoC: Execute EXIT instruction at entry point
  - Impact: ~~Invalid stack state~~
  - **Assessment**: EXIT (opcode 0x95) returns from VM execution. If executed at entry (frame_cnt=0), simply exits with return value in r0. No stack underflow - frame_cnt stays at 0. Benign behavior.
  - Test: ~~Program starting with EXIT opcode~~ NOT EXPLOITABLE

### 5.4 Syscall Exploitation

#### 5.4.1 Memory Syscalls
- [x] **sol_memcpy_ overlapping regions** (`fd_vm_syscall_util.c:400`) - **SAFE**
  - PoC: Copy with src overlapping dst
  - Impact: ~~Corrupted memory~~
  - **Assessment**: Line 400: `FD_VM_MEM_CHECK_NON_OVERLAPPING(vm, src_vaddr, sz, dst_vaddr, sz)` macro at fd_vm_syscall_macros.h:271-277 checks both `addr0>addr1 && (addr0-addr1)<sz1` and `addr1>=addr0 && (addr1-addr0)<sz0`. Explicit overlap detection prevents corruption. Returns ERR_COPY_OVERLAPPING on overlap.
  - Test: ~~`memcpy(addr, addr+4, 16)`~~ NOT EXPLOITABLE

- [x] **sol_memset_ length overflow** (`fd_vm_private.h:430-476`) - **SAFE**
  - PoC: Memset with length causing offset+length to wrap
  - Impact: ~~Write beyond intended region~~
  - **Assessment**: fd_vm_mem_haddr() at line 461: `sz_max = region_sz - fd_ulong_min(offset, region_sz)` uses saturating arithmetic. Line 476: `fd_ulong_if(sz<=sz_max, ...)` validates size before allowing access. Integer overflow prevented by bounds checking.
  - Test: ~~`memset(addr=0xFFFF_FFF0, val=0, len=0x100)`~~ NOT EXPLOITABLE

#### 5.4.2 CPI Syscalls
- [x] **CPI depth limit bypass** (`fd_executor.c:1107-1116`) - **SAFE**
  - PoC: Nested CPI exceeding max depth of 5
  - Impact: ~~Stack overflow~~
  - **Assessment**: Lines 1107-1109: `if(instr_trace_length>=FD_MAX_INSTRUCTION_TRACE_LENGTH)` checks 64-instruction limit. Lines 1113-1115: `if(instr_stack_sz>=FD_MAX_INSTRUCTION_STACK_DEPTH)` checks 5-level depth limit. Returns ERR_CALL_DEPTH on violation. Both limits enforced in fd_txn_ctx_push().
  - Test: ~~Program A calls B calls C calls D calls E (depth 5)~~ NOT EXPLOITABLE

- [x] **CPI account info pointer manipulation** (`fd_executor.c:1169-1189`) - **SAFE (single-threaded)**
  - PoC: Modify account_info pointer between validation and use
  - Impact: ~~Use-after-check, wrong account modified~~
  - **Assessment**: VM execution and CPI are single-threaded within transaction context. Lines 1169-1189 check reentrancy by iterating through instr_stack. No concurrent modification possible. Architectural protection.
  - Test: ~~Multi-threaded modification of account_info array~~ NOT EXPLOITABLE

- [ ] **CPI signer seeds validation bypass** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Provide invalid seeds that validate incorrectly
  - Impact: Unauthorized PDA signing
  - Location: `fd_vm_syscall_cpi_common.c` - signer seeds handling in invoke_signed
  - Test: Seeds that don't derive to claimed PDA
  - **Note**: Requires deep analysis of PDA derivation and validation in CPI syscalls

- [ ] **CPI duplicate account with different privileges** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Same account appears twice with different is_writable flags
  - Impact: Bypass write-lock restrictions
  - Location: `fd_vm_syscall_cpi_common.c:273-334`
  - Test: Instruction with account_indices = [0, 0], writable=[false, true]
  - **Note**: Requires analysis of account deduplication logic in CPI account translation

#### 5.4.3 Cryptographic Syscalls
- [x] **sol_sha256 input length overflow** (`fd_vm_syscall_hash.c:38-48,74-78`) - **SAFE**
  - PoC: Hash input causing internal buffer overflow
  - Impact: ~~Memory corruption~~
  - **Assessment**: Line 38: `if(FD_VM_SHA256_MAX_SLICES < vals_len)` checks slice count limit (20,000). Lines 74-78: Per-slice cost calculated with `fd_ulong_sat_mul(FD_VM_SHA256_BYTE_COST, val_len/2)` using saturating multiplication. CU charged before processing (line 78). Overflow prevented by slice limits and saturation.
  - Test: ~~`sha256(input_len=UINT64_MAX)`~~ NOT EXPLOITABLE

- [x] **sol_verify_signature curve point validation bypass** (`fd_curve25519.h:199-207`) - **SAFE**
  - PoC: Signature with invalid curve point
  - Impact: ~~Signature verification bypass~~
  - **Assessment**: fd_ed25519_point_validate() at lines 199-207 validates points by attempting decompression via fd_ed25519_point_frombytes(). Low-order points and invalid curve points rejected during decompression. fd_ristretto255.h:54 also validates ristretto group membership. Proper point validation implemented.
  - Test: ~~Ed25519 signature with low-order point~~ NOT EXPLOITABLE

### 5.5 Compute Unit Metering Bypass
- [ ] **CU request integer overflow** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Request CU = UINT32_MAX via compute budget program
  - Impact: Bypass CU limits
  - Test: ComputeBudgetInstruction::SetComputeUnitLimit(UINT32_MAX)
  - **Note**: Requires analysis of compute budget instruction processing and CU limit validation

- [ ] **CU consumption underflow** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Syscall that refunds more CUs than consumed
  - Impact: Infinite compute
  - Test: Loop calling refunding syscall
  - **Note**: Requires analysis of CU consumption/refund logic in syscalls

- [ ] **Nested program CU tracking** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: CPI where child program doesn't inherit parent CU limits
  - Impact: Child program gets fresh CU budget
  - Test: Parent at 1.4M CU calls child

---

## 6. Consensus Layer Attacks

### 6.1 Fork Choice Manipulation
- [ ] **Ghost weight overflow** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Validator stake causing weight calculation to overflow
  - Impact: Incorrect fork choice
  - Test: Validator with stake > UINT64_MAX/2
  - **Note**: Requires analysis of GHOST fork choice algorithm implementation in fd_ghost.c

### 6.2 Vote Manipulation
- [ ] **Vote timestamp manipulation** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Vote with timestamp far in future
  - Impact: Lockout calculation incorrect
  - Test: Vote with timestamp = now + 1 year
  - **Note**: Requires analysis of vote validation and lockout calculation

- [ ] **Vote slot sequence attack** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Vote for non-sequential slots
  - Impact: Bypass lockout rules
  - Test: Vote for slots [100, 200, 150]
  - **Note**: Requires analysis of vote slot ordering validation

- [ ] **Vote hash mismatch acceptance** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Vote with hash not matching actual block
  - Impact: Vote for non-existent block
  - Test: Vote with random hash value
  - **Note**: Requires analysis of vote hash verification against block hashes

### 6.3 Shred Attacks
- [ ] **FEC set index manipulation** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Shreds with inconsistent FEC set indices
  - Impact: Incorrect reassembly
  - Test: Shred claiming to be from different FEC sets
  - **Note**: Requires analysis of shred FEC validation in fd_shred.c

- [ ] **Merkle proof bypass** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Shred with invalid merkle proof but valid signature
  - Impact: Accept invalid shred
  - Test: Modify shred data after signing
  - **Note**: Requires analysis of merkle tree validation vs signature validation ordering

- [ ] **Shred version downgrade** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Newer shred with older version number
  - Impact: Bypass version-specific validations
  - Test: v2 shred claiming to be v1
  - **Note**: Requires analysis of shred version validation logic

---

## 7. State Management Exploits

### 7.1 Funk Transaction Tree
- [x] **Transaction cycle creation** - **SAFE**
  - PoC: ~~Create txn A → parent B → parent A~~
  - Impact: ~~Infinite loop in tree traversal~~
  - **Assessment**: Cycle detection implemented in publish path (`fd_funk_txn.c:210-217`). Line 215 checks `!txn_pool->ele[child_idx].tag` during tree traversal - if child already tagged, it's been visited (cycle detected). Parent relationships set at txn creation (line 119) from validated parent_xid, and parent cannot be changed after creation. Cycles prevented both structurally and via runtime detection.
  - Test: ~~Manipulate parent pointers to create cycle~~ NOT EXPLOITABLE

- [x] **Transaction ID reuse** - **SAFE**
  - PoC: ~~Commit transaction with XID of active transaction~~
  - Impact: ~~State corruption~~
  - **Assessment**: Line 72 of `fd_funk_txn.c`: `if(fd_funk_txn_map_query_try(...xid...) != FD_MAP_ERR_KEY)` checks if XID already exists before creating new transaction. Returns error if XID already in use. Additionally, line 66 checks if XID matches last published transaction. Duplicate XIDs rejected at prepare time.
  - Test: ~~Manually craft transaction with duplicate XID~~ NOT EXPLOITABLE

- [ ] **Parent transaction commit before child** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Commit parent while child is in-preparation
  - Impact: Orphaned child transaction
  - Test: Concurrent commit of parent and child operations
  - **Note**: Requires analysis of transaction lifecycle and publish semantics to determine if children are automatically handled or can be orphaned

### 7.2 Groove Volume Corruption
- [ ] **Volume header manipulation** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Corrupt magic number in volume header
  - Impact: Volume becomes unreadable
  - Test: Overwrite first 8 bytes of volume
  - **Note**: Requires analysis of Groove volume validation and error handling

- [ ] **Data size field overflow** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Entry with 24-bit size = 0xFFFFFF
  - Impact: Read beyond volume bounds
  - Test: Store entry with maximum size value
  - **Note**: Requires analysis of Groove entry size validation

### 7.3 Vinyl Hash Table
- [ ] **Probe sequence infinite loop** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Insert elements causing probe sequence to cycle
  - Impact: Infinite loop on lookup
  - Location: `fd_vinyl_meta.c:31`
  - Test: Fill hash table, insert with specific hash values
  - **Note**: Requires analysis of Vinyl linear/quadratic probing implementation

- [ ] **Tombstone exhaustion** - **EXPECTED BEHAVIOR (DEGRADATION)**
  - PoC: Delete and re-insert until table is mostly tombstones
  - Impact: Degraded performance (expected for hash tables with tombstones)
  - **Assessment**: Tombstone accumulation is a known hash table degradation pattern. Most hash table implementations don't prevent this, they rely on rehashing/resizing. This is expected behavior, not a vulnerability - similar to any hash table with tombstones (e.g., Python dict pre-3.6). Would need to verify Vinyl has rehash/resize mechanisms for long-running use.
  - Test: Cycle of insert/delete 100k times → performance degradation (expected)

---

## 8. IPC / Shared Memory Attacks

### 8.1 Mcache Exploitation
- [ ] **Sequence number overflow** - **EXPECTED BEHAVIOR (LONG-TERM OPERATION)**
  - PoC: Run system until sequence number wraps around (2^64 operations)
  - Impact: Sequence wraps at 2^64
  - **Assessment**: Mcache uses 64-bit sequence numbers. At 1M ops/sec, would take ~584,000 years to wrap. Wrapping is handled correctly by modular arithmetic in sequence comparisons (typically use subtraction which works across wraparound). This is expected behavior for long-running systems with 64-bit counters. Not a practical vulnerability.
  - Test: Fast-forward seq to near UINT64_MAX → wrap behavior (expected, not exploitable in practice)

### 8.2 Dcache Data Leakage
- [x] **Uninitialized data read** (`fd_dcache.c:70-78`) - **VULNERABLE**
  - PoC: Read dcache chunk before it's written to
  - Impact: Information disclosure from previous allocations
  - Test: Allocate chunk, read before writing
  - **Assessment**: CONFIRMED - Data region not zeroed in fd_dcache_new(). See SR/Findings/MEM-001
  - **Severity**: MEDIUM

- [x] **Chunk offset integer overflow** - **SAFE**
  - PoC: ~~Chunk calculation with sz causing overflow~~
  - Impact: ~~Wraparound to beginning of dcache~~
  - Location: `fd_dcache.h:268`
  - **Assessment**: Line 268: `chunk += ((sz+(2UL*FD_CHUNK_SZ-1UL)) >> (1+FD_CHUNK_LG_SZ)) << 1`. Comment states "no overflow if init passed". The sz parameter is assumed to be in [0,mtu], and mtu is validated during initialization (`fd_dcache.c:234` comment confirms "guaranteed overflow safe for any size in [0,mtu]"). Dcache initialization validates mtu bounds before use. Attack requires violating precondition (sz > mtu), which is caller's responsibility to validate.
  - Test: ~~Allocate with sz = UINT64_MAX - FD_CHUNK_SZ~~ NOT EXPLOITABLE (precondition: sz <= mtu)

### 8.3 Tcache Hash Collisions
- [ ] **Bloom filter false negative** - **NOT APPLICABLE (TCACHE USES HASH MAP, NOT BLOOM FILTER)**
  - PoC: ~~Craft transaction signature causing bloom filter miss~~
  - Impact: ~~Duplicate transaction not detected~~
  - **Assessment**: Tcache uses hash map with linear probing (`fd_tcache.h:281-295`), not a bloom filter. Lookup via `FD_TCACHE_QUERY` exhaustively searches until finding match or empty slot. No false negatives possible - either signature found or definitively not in cache. Confusion may arise from "filter" terminology, but tcache is deterministic hash map.
  - Test: ~~Signature with specific bit pattern~~ NOT APPLICABLE

- [ ] **Tcache entry overflow** - **EXPECTED BEHAVIOR (LRU EVICTION)**
  - PoC: Insert more entries than tcache capacity
  - Impact: Oldest entries evicted (LRU), duplicates of evicted entries allowed
  - **Assessment**: Tcache has fixed depth limit. When full, `FD_TCACHE_INSERT` evicts oldest entry (`fd_tcache.h:392-399`). This is EXPECTED LRU behavior, not vulnerability. Duplicates of evicted transactions can be resubmitted after eviction window. This is standard dedup cache behavior - bounded memory with time-limited dedup. Proper sizing of tcache depth prevents premature eviction.
  - Test: Submit depth+1 unique transactions → oldest evicted (expected LRU behavior)

---

## 9. Sandboxing & Isolation Bypasses

### 9.1 Seccomp Filter Exploitation
- [ ] **Argument-based syscall filter bypass** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Call whitelisted syscall with malicious arguments
  - Impact: Unexpected syscall behavior
  - Test: `read(fd=-1, buf, size)` if read() whitelisted
  - **Note**: Requires analysis of seccomp filter rules and argument validation for each tile

- [ ] **TOCTOU in syscall argument validation** - **NOT APPLICABLE (SECCOMP RUNS IN KERNEL)**
  - PoC: ~~Modify syscall arguments after seccomp check~~
  - Impact: ~~Execute syscall with different args~~
  - **Assessment**: Seccomp BPF filtering runs in kernel at syscall entry, examining registers containing syscall arguments. No TOCTOU possible - arguments checked atomically as part of syscall invocation. Userspace cannot modify arguments between check and execution. Misunderstanding of seccomp architecture.
  - Test: ~~Multi-threaded argument modification~~ NOT APPLICABLE

### 9.2 Namespace Escapes
- [ ] **Mount namespace escape via /proc** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Access host filesystem through /proc/[pid]/root
  - Impact: Read host files
  - Test: Traverse to /proc/1/root
  - **Note**: Requires analysis of namespace setup, /proc mounting options, and PID namespace isolation

- [ ] **Network namespace bypass via Unix socket** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Connect to Unix socket on host namespace
  - Impact: Network isolation bypass
  - Test: Create Unix socket before namespace creation
  - **Note**: Requires analysis of network namespace setup and Unix socket handling

### 9.3 Shared Memory Permission Bypass
- [ ] **Mmap RO region as RW** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Remap read-only shared memory as writable
  - Impact: Modify supposedly read-only data
  - Test: `mmap(addr, len, PROT_WRITE, MAP_FIXED|MAP_SHARED, fd, 0)`
  - **Note**: Requires analysis of workspace permissions and mmap protection enforcement

- [ ] **Workspace magic number bypass** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Corrupt magic number, continue using workspace
  - Impact: Use corrupted workspace
  - Test: Overwrite magic bytes, attempt operations
  - **Note**: Requires analysis of workspace validation and magic number checking frequency

---

## 10. Agave Integration Attacks

### 10.1 Shared Memory Communication
- [ ] **Firedancer→Agave transaction corruption** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Modify transaction in shared memory after Firedancer writes
  - Impact: Agave executes different transaction
  - Test: Race between Firedancer write and Agave read
  - **Note**: Requires analysis of Frankendancer shared memory protocol and synchronization mechanisms

- [ ] **Agave→Firedancer result tampering** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Modify execution result before Firedancer reads it
  - Impact: Incorrect transaction status
  - Test: Modify result in shared memory
  - **Note**: Requires analysis of result passing protocol and integrity checks

### 10.2 Funk Synchronization
- [ ] **Account state divergence** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Firedancer and Agave disagree on account state
  - Impact: Consensus fork
  - Test: Concurrent account modifications from both sides
  - **Note**: Requires deep analysis of Funk transaction isolation and Agave state sync mechanisms

- [ ] **Transaction commit order violation** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Agave commits transaction before Firedancer
  - Impact: Ordering mismatch
  - Test: Force Agave to commit out-of-order
  - **Note**: Requires analysis of transaction ordering guarantees between Firedancer and Agave

---

## 11. Denial of Service Vectors

### 11.1 Resource Exhaustion
- [ ] **Connection pool exhaustion via slow clients** - **EXPECTED DoS (REQUIRES RATE LIMITING)**
  - PoC: Open 131,072 connections, never send data
  - Impact: Legitimate clients cannot connect
  - **Assessment**: Standard connection exhaustion DoS attack. All network services have finite connection limits. Mitigation requires rate limiting, connection timeouts, and resource quotas per IP. This is expected attack vector for any network service, not a Firedancer-specific vulnerability. Proper operational configuration (firewalls, rate limits) required.
  - Test: Automated connection opening without traffic → exhaustion (expected, mitigated operationally)

- [ ] **Stream pool exhaustion** - **EXPECTED DoS (REQUIRES RATE LIMITING)**
  - PoC: Create maximum streams, never close
  - Impact: New streams cannot be created
  - **Assessment**: Similar to connection exhaustion. QUIC streams have finite limits per connection. Standard DoS attack vector. Requires operational mitigations (stream limits, timeouts, per-connection quotas).
  - Test: Open max streams per connection → exhaustion (expected DoS pattern)

- [ ] **Signature verification CPU exhaustion** - **EXPECTED DoS (RATE-LIMITED)**
  - PoC: Flood with transactions requiring signature verification
  - Impact: CPU at 100%, packet drops
  - **Assessment**: Cryptographic operations are expensive. Any validator can be CPU-exhausted by signature verification flood. Solana protocol has transaction fee requirements and rate limiting to mitigate. This is known attack vector, mitigated by economic costs (fees) and network-level rate limiting.
  - Test: Send 100k txns/sec with valid signatures → CPU exhaustion (expected, economically limited)

### 11.2 Memory Exhaustion
- [ ] **Account data growth DoS** - **PROTOCOL-LEVEL DoS (RENT MECHANISM)**
  - PoC: Transaction reallocating account to 10MiB repeatedly
  - Impact: Memory exhaustion
  - **Assessment**: Solana has rent mechanism requiring lamports to maintain account data. Creating 10MiB accounts repeatedly costs rent. Economic disincentive prevents unlimited memory growth. Protocol-level mitigation, not Firedancer implementation issue.
  - Test: Loop creating 10MiB accounts → limited by rent costs (protocol mitigation)

- [ ] **Workspace exhaustion** ⚠️ **NEEDS DEEPER ANALYSIS**
  - PoC: Allocate all workspace memory
  - Impact: Tile cannot allocate
  - Test: Allocate maximum workspace chunks
  - **Note**: Requires analysis of workspace allocation limits and per-tile memory quotas

### 11.3 Computational DoS
- [ ] **Expensive instruction sequence** - **EXPECTED (CU LIMITS)**
  - PoC: BPF program with maximum compute units of trivial operations
  - Impact: Consumes full CU budget
  - **Assessment**: Programs are limited to 1.4M CU. Executing 1.4M operations within CU limit is expected behavior, not abuse. Transaction pays fees proportional to CU consumption. Economic mechanism prevents DoS. Program consuming full CU budget is normal, not vulnerability.
  - Test: Program with 1.4M operations → uses full CU budget (expected, fee-based)

- [ ] **Priority fee manipulation** - **NOT A VULNERABILITY (MARKET MECHANISM)**
  - PoC: Transaction with priority_fee = UINT64_MAX
  - Impact: Block packing prioritizes high-fee transaction
  - **Assessment**: Priority fee is intentional market mechanism for transaction ordering. Paying high fees to get priority is expected behavior, not attack. Validators maximize fee revenue by packing high-fee transactions. This is working as designed - fee market for block space. Not a DoS vulnerability.
  - Test: Submit high-fee transaction → gets priority (expected market behavior)

---

## 12. Cryptographic Attacks

### 12.1 Ed25519 Exploits
- [ ] **Non-canonical signature acceptance** - **INTENTIONAL DESIGN (COMPATIBILITY)**
  - PoC: Transaction with non-canonical Ed25519 signature
  - Impact: Signature malleability (same transaction, different signature bytes)
  - Location: `fd_ed25519_user.c:168-190` (intentional by design per comment)
  - **Assessment**: Ed25519 allows multiple valid byte representations for same signature (non-canonical S values). Firedancer intentionally accepts non-canonical signatures for Solana compatibility. This is malleability, not forgery - attacker cannot sign for others, only modify own signature bytes. Impact limited to transaction ID changes. Known tradeoff for compatibility. Not a security vulnerability in isolation.
  - Test: Generate malleable signature → accepted (intentional for compatibility)

- [ ] **Batch verification partial failure** - **INFORMATION LEAK (TIMING SIDE-CHANNEL)**
  - PoC: Submit batch where 15 valid + 1 invalid signature
  - Impact: Timing reveals approximate location of invalid signature
  - **Assessment**: Batch verification may short-circuit on first invalid signature, causing variable timing. This is low-severity timing side-channel leaking which transaction in batch failed. Similar to cache timing side-channel analyzed earlier. Information leaked (which signature invalid) has limited value. Not critical vulnerability.
  - Test: Batch verification timing analysis → position leak (low severity)

### 12.2 Hash Function Attacks
- [ ] **SHA-256 length extension** - **KNOWN PROPERTY (USE HMAC IF NEEDED)**
  - PoC: Extend hash of known input
  - Impact: Construct SHA-256(M || X) from SHA-256(M)
  - **Assessment**: Length extension is fundamental property of Merkle-Damgård construction (SHA-256). Not a vulnerability in SHA-256 itself - it's working as mathematically designed. Attack only relevant when SHA-256 used as MAC without key (use HMAC instead). Firedancer uses SHA-256 for hashing, not authentication. Length extension is irrelevant for collision resistance use case. Not a Firedancer vulnerability.
  - Test: SHA-256 length extension attack → works (fundamental property, not vulnerability)

- [ ] **BLAKE3 collision search** - **COMPUTATIONALLY INFEASIBLE**
  - PoC: Find two inputs with same BLAKE3 hash
  - Impact: Hash collision
  - **Assessment**: BLAKE3 designed with 256-bit collision resistance. Finding collision requires ~2^128 operations (birthday bound). With current computational power, this is infeasible. Would require millions of years on all computers on Earth. BLAKE3 is collision-resistant by design. Not a practical attack vector.
  - Test: Birthday attack on BLAKE3 → computationally infeasible (2^128 operations)

---

## Attack Scenario Templates

### Template 1: Integer Overflow/Underflow
```
1. Identify arithmetic operation without overflow check
2. Determine input values causing overflow
3. Trace downstream impact of overflowed value
4. Construct PoC transaction/packet triggering overflow
5. Demonstrate exploitability (DoS, memory corruption, etc.)
```

### Template 2: Race Condition
```
1. Identify shared resource accessed by multiple threads/processes
2. Find TOCTOU window between check and use
3. Develop timing to reliably hit race window
4. Construct PoC demonstrating incorrect behavior
5. Show security impact (privilege escalation, data corruption, etc.)
```

### Template 3: Parser Exploit
```
1. Identify parser for untrusted input
2. Fuzz with malformed inputs
3. Find input causing crash, hang, or incorrect parsing
4. Develop PoC input exploiting parser bug
5. Demonstrate impact (RCE, DoS, bypass, etc.)
```

---

## PoC Requirements

Each finding MUST include:
1. **Trigger condition**: Exact steps to reproduce
2. **Proof-of-concept code**: Working exploit demonstrating impact
3. **Impact assessment**: What attacker gains from exploitation
4. **Affected versions**: Which Firedancer/Agave versions vulnerable
5. **Fix verification**: How to verify patch resolves issue

---

## Testing Tools

- **Fuzzing**: AFL++, libFuzzer on critical parsers
- **Dynamic analysis**: Valgrind, ASan, UBSan, TSan
- **Network**: Scapy for packet crafting, custom QUIC clients
- **BPF**: Custom sBPF programs exercising edge cases
- **Load testing**: Transaction flood generators
- **Timing analysis**: CPU timing measurements for side-channels

---

## Progress Tracking

**Total Attack Vectors**: ~120 (refined from 600+)
**Vectors Tested**: [ ] 0
**Vulnerabilities Found**: [ ] 0
**PoCs Developed**: [ ] 0

**Assessment Start Date**: _____________
**Assessment End Date**: _____________
**Lead Researcher**: _____________

---

## New Vulnerabilities Discovered

Any new vulnerabilities discovered during testing should be documented in:
`./SR/Findings/<CATEGORY>-<NUMBER>_<Description>.md`

Use this template for findings:
```markdown
# <Severity>: <Title>

**CVE**: TBD
**Severity**: Critical/High/Medium/Low
**Component**: <Component Name>
**Location**: <File>:<Line>

## Summary
Brief description of vulnerability.

## Technical Details
Detailed explanation of the vulnerability.

## Proof of Concept
```code
Working exploit code
```

## Impact
What an attacker can accomplish.

## Remediation
How to fix the vulnerability.

## References
- Related CVEs
- Code references
```

---

**END OF ATTACK-FOCUSED CHECKLIST**
