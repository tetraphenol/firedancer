# Frankendancer Fuzzing Target Prioritization

**Document Version:** 2.0
**Date:** November 11, 2025
**Purpose:** Prioritized list of components for comprehensive coverage-guided fuzzing campaigns

**Scope:** This document focuses exclusively on components included in **Frankendancer** (the hybrid validator using Firedancer networking + Agave execution). Pure Firedancer-only components are excluded.

---

## Executive Summary

This document identifies and prioritizes fuzzing targets within the Frankendancer validator codebase. Prioritization is based on:

1. **Code Complexity** - More complex code has higher bug density
2. **Fuzzer-Friendliness** - Binary formats yield better than text-based formats
3. **Isolation Effort** - Ease of creating fuzzing harnesses
4. **Existing Coverage** - Less-tested code offers better ROI
5. **Maturity** - Novel/generated code more likely to contain bugs
6. **Security Impact** - Consensus-critical and sandbox-escape vulnerabilities prioritized

### Current Fuzzing Coverage

**Existing Fuzzers Identified:** 20+ fuzzing harnesses already exist
- ✅ Transaction parser (`fuzz_txn_parse.c`)
- ✅ Shred parser (`fuzz_shred_parse.c`)
- ✅ Gossip messages (`fuzz_gossip_msg_parse.c`)
- ✅ TLS handshake (`fuzz_tls_msg_parser.c`)
- ✅ HTTP/2 & gRPC (`fuzz_h2.c`, `fuzz_grpc_codec.c`)
- ✅ Bincode types (partial - `fuzz_types_decode.c`)
- ✅ Snapshot parsers (partial - `fuzz_ssmanifest_parser.c`)
- ❌ **sBPF VM interpreter** - NO COMPREHENSIVE FUZZER (Agave component in Frankendancer)
- ❌ **CPI validation logic** - NOT FUZZED (Agave component in Frankendancer)
- ❌ **QUIC frame parsing** (only transport params fuzzed - Firedancer component)
- ❌ **Shred parsing** (only basic parsing fuzzed - Firedancer component)

---

## Top-Priority Fuzzing Targets

### Tier 1: Critical Unfuzzed Components

#### 1. sBPF VM Interpreter Core ⭐⭐⭐⭐⭐

**⚠️ NOTE:** This component is part of the **Agave runtime** in Frankendancer (Rust implementation). While Firedancer includes C implementations of VM code in `src/flamenco/vm/`, these are NOT currently used in production Frankendancer builds. Fuzzing would need to target the Agave Rust implementation instead.

**Firedancer C Implementation (Not Used in Frankendancer):**
- `src/flamenco/vm/fd_vm_interp_core.c` (1,253 LOC)
- `src/flamenco/vm/fd_vm_private.h` (memory translation)
- `src/flamenco/vm/fd_vm.c` (VM setup, 35 KB)

**Relevance to Frankendancer:** ⚠️ **LOW** - This is handled by Agave's Rust VM implementation

**Complexity:** ⭐⭐⭐⭐⭐ (Extremely High)
- 100+ eBPF instruction opcodes
- Complex jump table dispatch
- Memory region management with TLB
- Call stack management
- Register state tracking

**Fuzzer-Friendliness:** ⭐⭐⭐⭐⭐ (Excellent)
- **Input Format:** Raw BPF bytecode (high-entropy binary)
- **Input Size:** Variable (program size)
- **State Space:** Massive (2^64 per register × 11 registers × memory states)

**Known Critical Vulnerabilities:**
- Binary search out-of-bounds when `input_mem_regions_cnt == 0` (`fd_vm_private.h:296`)
- Potential instruction pointer validation issues
- Stack overflow edge cases

**Existing Test Coverage:**
- Unit tests: `test_vm_instr.c`, `test_vm_base.c`
- **No comprehensive fuzzing harness**

**Attack Surface:**
- Executes untrusted BPF programs from blockchain transactions
- VM escape = complete validator compromise
- Consensus-critical (divergent execution = fork)

**Recommended Fuzzing Strategy:**

```c
/* Fuzzer harness pseudocode */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. Interpret first bytes as VM configuration
  //    - Number of memory regions (0-16)
  //    - Memory region properties (size, permissions)
  //    - Initial register values

  // 2. Remaining bytes = BPF program bytecode
  //    - Constrain to valid instruction count (< 10,000)
  //    - Allow malformed instructions (fuzzer will explore)

  // 3. Setup VM with fuzzed configuration
  fd_vm_t vm = setup_vm_from_fuzz_input(data, config_size);

  // 4. Execute program with instrumentation
  //    - Track coverage (AFL++/libFuzzer automatic)
  //    - Detect: crashes, hangs, assertion failures
  //    - Validate: no OOB memory access (ASan)

  int result = fd_vm_exec(&vm);

  // 5. Verify VM state consistency
  validate_vm_state(&vm);

  return 0;
}
```

**Specific Test Cases to Inject:**
- Zero memory regions (trigger known OOB bug)
- Maximum call depth (4096 frames)
- Invalid jump targets (beyond program bounds)
- All arithmetic edge cases (division by zero, overflow)
- Register r10 (frame pointer) manipulation
- Memory access at region boundaries
- Syscall invocation with extreme parameters

**Harness Development Effort:** ⭐⭐⭐ (MEDIUM)
- Leverage existing `test_vm_instr.c` infrastructure
- VM setup requires memory region configuration
- Need BPF program generator (constrained randomization)

**Expected Bug Yield:** ⭐⭐⭐⭐⭐ (VERY HIGH)
- Complex, novel interpreter implementation
- Known critical bug already exists
- Insufficient fuzzing coverage historically

**Priority for Frankendancer:** ⚠️ **DEFERRED** - Target Agave's Rust implementation instead, or defer until pure Firedancer

---

#### 2. Bincode Type Deserializers ⭐⭐⭐⭐⭐

**Relevance to Frankendancer:** ✅ **HIGH** - Used by both Firedancer and Agave components for IPC

**Files:**
- `src/flamenco/types/fd_types.c` (15,427 LOC - **MASSIVE AUTO-GENERATED CODE**)
- `src/flamenco/types/fd_types.h` (type definitions)
- `src/flamenco/types/fuzz_types_decode.c` (existing partial fuzzer)

**Complexity:** ⭐⭐⭐⭐⭐ (Extremely High)
- 15,000+ lines of auto-generated deserialization code
- 100+ Solana data structures (blocks, transactions, votes, accounts)
- Nested structures with recursive types
- Variable-length arrays and optional fields
- Compact integer encoding (compact-u16, compact-u64)

**Fuzzer-Friendliness:** ⭐⭐⭐⭐⭐ (Excellent)
- **Input Format:** Rust bincode binary format (high entropy)
- **Structure:** Length-prefixed, self-describing
- **Mutation-Friendly:** Small changes = structural variations

**Existing Coverage:**
- Partial fuzzer exists: `fuzz_types_decode.c`
- **Gap:** Only fuzzes subset of types, blacklist excludes some

**High-Value Unfuzzed Types:**

| Type | File/Struct | Impact | Lines of Code |
|------|-------------|--------|---------------|
| `fd_block_t` | Block deserialization | Fork risk | ~500 LOC |
| `fd_vote_t` | Vote messages | Consensus | ~200 LOC |
| `fd_epoch_stakes_t` | Stake distribution | Consensus | ~300 LOC |
| `fd_transaction_t` | Alternative txn parser | Execution | ~400 LOC |
| `fd_account_meta_t` | Account metadata | State | ~150 LOC |
| `fd_slot_hashes_t` | Slot history | Consensus | ~100 LOC |

**Known Issues:**
- Blacklist indicates some encoders unimplemented (`fd_tower_sync`)
- Auto-generated code = less manual review

**Recommended Fuzzing Strategy:**

```c
/* Enhanced fuzzer structure */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. Select type to deserialize (use first byte as type selector)
  ulong type_idx = data[0] % NUM_FUZZABLE_TYPES;
  fd_types_vt_t const * type_meta = get_type_metadata(type_idx);

  // 2. Deserialize with bincode decoder
  fd_bincode_decode_ctx_t ctx = {
    .data = data + 1,
    .dataend = data + size
  };

  void *decoded = NULL;
  int err = decode_type(type_meta, &ctx, &decoded);

  if (err == FD_BINCODE_SUCCESS) {
    // 3. Re-encode and compare (round-trip test)
    uchar re_encoded[MAX_SIZE];
    size_t encoded_sz = 0;
    encode_type(type_meta, decoded, re_encoded, sizeof(re_encoded), &encoded_sz);

    // 4. Decode again and verify equality
    void *decoded2 = NULL;
    decode_type(type_meta, re_encoded, &decoded2);

    assert(types_equal(decoded, decoded2));
  }

  return 0;
}
```

**Specific Mutations to Inject:**
- Extreme length prefixes (0, 1, UINT64_MAX)
- Deeply nested structures (100+ levels)
- Optional fields (Some/None variations)
- Enum discriminants (valid and invalid values)
- Compact-u16/u64 edge cases (multi-byte encodings)
- Truncated inputs (partial structures)

**Harness Development Effort:** ⭐ (LOW)
- Existing `fuzz_types_decode.c` provides complete framework
- Only need to expand type coverage and remove blacklist

**Expected Bug Yield:** ⭐⭐⭐⭐⭐ (VERY HIGH)
- Massive auto-generated code surface
- Complex nested structures
- Critical for consensus (blocks, votes)

**Priority:** **CRITICAL - Start in parallel with VM fuzzing**

---

#### 3. Shred Parser & FEC Decoder ⭐⭐⭐⭐

**Relevance to Frankendancer:** ✅ **HIGH** - Used by Firedancer's `shred` tile for block distribution

**Files (Used in Frankendancer):**
- `src/ballet/shred/fd_shred.c` (shred structure parsing)
- `src/ballet/shred/fd_deshredder.c` (FEC decoding)
- `src/ballet/shred/fuzz_shred_parse.c` (existing basic fuzzer)

**Files (NOT in Frankendancer - Pure Firedancer Only):**
- ~~`src/discof/reasm/fd_reasm.c` (reassembly state machine, 507 LOC)~~ - Used only by pure Firedancer's `repair` tile

**Complexity:** ⭐⭐⭐⭐ (High)
- Shred header parsing (88-89 byte headers)
- FEC (Forward Error Correction) reconstruction
- Merkle proof validation
- State machine for multi-shred reassembly
- CMR (Chained Merkle Root) validation

**Fuzzer-Friendliness:** ⭐⭐⭐⭐⭐ (Excellent)
- **Input Format:** Binary shred format (1,203-1,228 bytes)
- **Structure:** Fixed header + variable payload
- **State Machine:** Multi-input state (sequence of shreds)

**Known Issues:**
- FEC set index bounds checking
- Duplicate shred handling
- Merkle proof validation edge cases

**Existing Coverage:**
- Basic fuzzer: `fuzz_shred_parse.c` (single shred parsing)
- **Gap:** Limited FEC edge case coverage
- **Gap:** Merkle proof validation not thoroughly fuzzed

**Attack Surface:**
- Network-facing (Turbine protocol)
- Consensus-critical (block propagation)
- Byzantine validators can send equivocating shreds

**Recommended Fuzzing Strategy:**

```c
/* Shred parsing and FEC decoding fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < FD_SHRED_MIN_SZ || size > FD_SHRED_MAX_SZ) return 0;

  // 1. Parse shred header and payload
  fd_shred_t shred;
  int parse_result = fd_shred_parse(&shred, data, size);

  if (parse_result == FD_SHRED_PARSE_SUCCESS) {
    // 2. Validate shred structure
    assert(fd_shred_is_valid(&shred));

    // 3. Test FEC decoding if this is a coding shred
    if (fd_shred_is_code(&shred)) {
      fd_fec_set_t fec_set;
      fd_fec_set_init(&fec_set);

      // Attempt FEC reconstruction
      fd_deshredder_add_shred(&fec_set, &shred);

      // Verify FEC invariants
      validate_fec_set(&fec_set);
    }

    // 4. Validate merkle proof
    if (shred.merkle_proof_present) {
      assert(fd_shred_verify_merkle_proof(&shred));
    }
  }

  return 0;
}
```

**Specific Test Cases:**
- FEC set with missing shreds (incomplete recovery)
- Shreds with invalid merkle proofs
- Exceed 67 FEC sets per slot (DoS)
- Shred index > 32,767 (max index)
- Invalid FEC indices
- Malformed shred headers

**Harness Development Effort:** ⭐⭐ (LOW-MEDIUM)
- Extend existing `fuzz_shred_parse.c`
- Add FEC decoding edge cases
- Improve merkle proof validation coverage

**Expected Bug Yield:** ⭐⭐⭐⭐ (HIGH)
- Complex binary parsing
- Consensus-critical component
- Network-facing attack surface

**Priority:** **HIGH - Week 2-3 of campaign**

---

#### 4. CPI (Cross-Program Invocation) Validation ⭐⭐⭐⭐

**⚠️ NOTE:** Like the sBPF VM, CPI validation is part of the **Agave runtime** in Frankendancer. The C implementation in Firedancer is not used in production Frankendancer builds.

**Relevance to Frankendancer:** ⚠️ **LOW** - This is handled by Agave's Rust implementation

**Firedancer C Implementation (Not Used in Frankendancer):**
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c` (complex validation logic)
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c` (CPI syscalls)

**Complexity:** ⭐⭐⭐⭐⭐ (Extremely High)
- Account permission validation (read/write/signer)
- Account ownership checks
- Duplicate account detection
- Account length validation
- Program ID validation
- Privilege escalation prevention

**Fuzzer-Friendliness:** ⭐⭐⭐⭐ (Good)
- **Input Format:** CPI instruction structure (binary)
- **Parameters:** Account indices, permissions, data
- **State:** Multiple accounts with metadata

**Known Critical Vulnerabilities:**
- **Account length TOCTOU race** (`fd_vm_syscall_cpi_common.c:163`)
  - Length pointer modified between check and use
  - Enables buffer overflow
- **Duplicate account validation bypass** (`fd_vm_syscall_cpi_common.c:331`)
  - Dead code after break statement
  - Duplicate accounts bypass validation
- **Incomplete owner validation** (various CPI paths)
  - Writable accounts not always checked for ownership

**Existing Coverage:**
- Unit tests: `test_vm_syscall_cpi.c`
- **No dedicated fuzzer** for CPI validation logic

**Attack Surface:**
- Invoked by untrusted BPF programs
- Privilege escalation vector
- Account corruption risk

**Recommended Fuzzing Strategy:**

```c
/* CPI validation fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. Parse fuzzer input as CPI instruction structure
  //    - Number of accounts (0-128)
  //    - Account indices (each 0-255)
  //    - Account permissions (read/write/signer bits)
  //    - Program ID
  //    - Instruction data

  if (size < 4) return 0;

  uchar num_accounts = data[0] % 128;
  uchar *account_indices = malloc(num_accounts);
  uchar *account_perms = malloc(num_accounts);

  memcpy(account_indices, data + 1, num_accounts);
  memcpy(account_perms, data + 1 + num_accounts, num_accounts);

  // 2. Setup transaction context with fuzzed accounts
  fd_exec_txn_ctx_t txn_ctx;
  setup_txn_ctx(&txn_ctx, num_accounts, account_indices, account_perms);

  // 3. Invoke CPI validation (actual code under test)
  int result = fd_vm_syscall_cpi_validate(
    &txn_ctx,
    account_indices,
    num_accounts,
    ...
  );

  // 4. If validation passes, verify consistency:
  //    - No duplicate writable accounts
  //    - Owner matches for writable accounts
  //    - Account indices in bounds

  if (result == FD_VM_SUCCESS) {
    verify_cpi_invariants(&txn_ctx, account_indices, num_accounts);
  }

  return 0;
}
```

**Specific Test Cases:**
- Duplicate account indices (trigger known bug)
- Same account marked read+write in different positions
- Account owned by program A, invoked by program B
- Account indices >= transaction account count
- Zero accounts
- 128 accounts (maximum)
- Concurrent modification of account length (TOCTOU)

**Harness Development Effort:** ⭐⭐⭐⭐ (HIGH)
- Requires transaction context setup
- Account metadata initialization
- VM state preparation
- Complex invariant validation

**Expected Bug Yield:** ⭐⭐⭐⭐⭐ (VERY HIGH)
- Multiple known critical bugs
- Complex validation logic
- Privilege escalation risk

**Priority for Frankendancer:** ⚠️ **DEFERRED** - Target Agave's Rust implementation instead, or defer until pure Firedancer

---

#### 5. QUIC Frame Parser (Extended Coverage) ⭐⭐⭐⭐⭐

**Relevance to Frankendancer:** ✅ **CRITICAL** - Used by Firedancer's `quic` tile, front-line network defense

**Files:**
- `src/waltz/quic/templ/fd_quic_parsers.h` (template-based parser)
- `src/waltz/quic/templ/fd_quic_frame.c` (frame structures)
- `src/waltz/quic/templ/fuzz_quic_parse_transport_params.c` (existing partial fuzzer)

**Complexity:** ⭐⭐⭐ (Medium)
- 16+ QUIC frame types
- Variable-length integer encoding (varints)
- Frame-specific payload parsing
- Connection state dependency

**Fuzzer-Friendliness:** ⭐⭐⭐⭐⭐ (Excellent)
- **Input Format:** Binary QUIC frames
- **Structure:** Type byte + variable-length fields
- **High Entropy:** Variable-length integers, arbitrary payloads

**Existing Coverage:**
- Only transport parameters fuzzed: `fuzz_quic_parse_transport_params.c`
- **Gap:** Most frame types NOT fuzzed

**Unfuzzed Frame Types:**

| Frame Type | Opcode | Complexity | Risk |
|------------|--------|------------|------|
| STREAM | 0x08-0x0F | HIGH | Buffer overflow |
| ACK | 0x02-0x03 | HIGH | Range parsing DoS |
| CONNECTION_CLOSE | 0x1C-0x1D | MEDIUM | Reason string overflow |
| CRYPTO | 0x06 | HIGH | TLS handshake data |
| NEW_CONNECTION_ID | 0x18 | MEDIUM | Connection ID exhaustion |
| PATH_CHALLENGE/RESPONSE | 0x1A-0x1B | LOW | Spoofing |
| RESET_STREAM | 0x04 | MEDIUM | State confusion |

**Known Issues:**
- Connection ID hash collision (weak hash function)
- Varint decoding trusts MSB without full validation

**Recommended Fuzzing Strategy:**

```c
/* QUIC frame fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // 1. Parse frame type from first byte
  if (size < 1) return 0;

  uchar frame_type = data[0];

  // 2. Initialize QUIC connection context
  fd_quic_conn_t conn;
  fd_quic_conn_init(&conn);

  // 3. Parse frame with appropriate handler
  fd_quic_frame_t frame;
  int result = fd_quic_frame_parse(
    &frame,
    data,
    size,
    &conn
  );

  // 4. If parse succeeds, validate frame semantics
  if (result >= 0) {
    validate_frame_consistency(&frame, &conn);
  }

  return 0;
}
```

**Specific Test Cases:**
- STREAM frame with offset + length > UINT64_MAX
- ACK frame with 1000+ ACK ranges (gap parsing)
- CRYPTO frame with handshake data > MTU
- NEW_CONNECTION_ID with zero-length ID
- CONNECTION_CLOSE with 1MB error string
- Malformed varints (truncated, oversized)

**Harness Development Effort:** ⭐⭐ (LOW-MEDIUM)
- Extend existing transport params fuzzer
- Add connection state setup
- Frame type dispatch logic

**Expected Bug Yield:** ⭐⭐⭐⭐ (HIGH)
- Template-generated code (less review)
- Network-facing attack surface
- Variable-length parsing complexity

**Priority:** **CRITICAL - Week 1-2 of campaign** (Front-line DoS defense)

---

### Tier 2: Existing Fuzzers Needing Enhancement

#### 6. Snapshot Manifest Parser ⭐⭐⭐⭐

**Files:**
- `src/discof/restore/utils/fd_ssmanifest_parser.c` (1,676 LOC)
- `src/discof/restore/utils/fd_slot_delta_parser.c` (18,000 LOC)
- `src/discof/restore/utils/fd_ssparse.c` (26,000 LOC)

**Existing Fuzzers:**
- ✅ `fuzz_ssmanifest_parser.c`
- ✅ `fuzz_slot_delta_parser.c`
- ✅ `fuzz_snapshot_parser.c`

**Enhancement Needed:**
- **Corpus Quality:** Likely limited initial corpus
- **Structure-Aware Mutations:** JSON/binary hybrid format
- **Edge Cases:** Extreme file sizes, nested structures

**Recommended Enhancements:**

1. **Expand Corpus:**
   - Collect real mainnet snapshot manifests
   - Generate synthetic edge cases (empty, minimal, maximal)

2. **Structure-Aware Fuzzing:**
   ```bash
   # Use AFL++ custom mutator for JSON
   AFL_CUSTOM_MUTATOR_LIBRARY=./json_mutator.so afl-fuzz \
     -i snapshot_corpus/ -o findings/ ./fuzz_ssmanifest_parser @@
   ```

3. **Specific Injection Tests:**
   - Manifest with 1M file entries
   - Nested directory depth = 100
   - File sizes = UINT64_MAX
   - Malformed UTF-8 in filenames
   - Truncated manifests

**Priority:** **MEDIUM - Week 4-5 of campaign**

---

#### 7. Transaction Parser (Edge Case Focus) ⭐⭐⭐

**Files:**
- `src/ballet/txn/fd_txn_parse.c` (252 LOC)
- `src/ballet/txn/fuzz_txn_parse.c` (existing fuzzer)

**Existing Coverage:** ⭐⭐⭐ (Good)
- Well-tested parser with clear invariants
- Existing fuzzer covers basic cases

**Enhancement Focus:**
1. **Extreme Values:**
   - 127 signatures (theoretical max)
   - 128 accounts (max)
   - 64 instructions (max)
   - Instruction data = MTU - headers

2. **Compact-u16 Edge Cases:**
   - Single-byte encoding (0-127)
   - Two-byte encoding (128-16,383)
   - Three-byte encoding (16,384-65,535)
   - Invalid encodings (non-minimal)

3. **Address Lookup Tables:**
   - Max lookup tables (127)
   - Conflicting writable/readonly indices

**Priority:** **LOW - Week 6+ (already well-fuzzed)**

---

#### 8. Gossip Message Parser ⭐⭐⭐

**Files:**
- `src/flamenco/gossip/fd_gossip_msg_parse.c`
- `src/flamenco/gossip/fuzz_gossip_msg_parse.c` (existing)

**Enhancement Focus:**
1. **Vote Messages:**
   - Conflicting votes (same slot, different hashes)
   - Vote timestamps (extreme values)
   - Malformed vote structures

2. **Duplicate Detection:**
   - Inject duplicate messages
   - Test bloom filter false positive rate

3. **Peer Lists:**
   - 1000+ peers
   - Invalid peer IPs/ports

**Priority:** **LOW - Week 6+**

---

### Tier 3: Novel/Complex Components Without Fuzzers

#### 9. ~~Equivocation Detection State Machine~~ ❌ NOT IN FRANKENDANCER

**⚠️ REMOVED:** The equivocation detection component (`src/choreo/eqvoc/`) is only used in pure Firedancer, not in Frankendancer. This component is part of the consensus layer that's currently handled by Agave.

---

#### 10. TLS ASN.1 Certificate Parser ⭐⭐⭐

**Relevance to Frankendancer:** ✅ **MEDIUM** - Used by Firedancer's `quic` tile for TLS 1.3 handshakes

**Files:**
- `src/waltz/tls/fd_tls_asn1.c` (ASN.1 DER parsing)
- `src/waltz/tls/fuzz_tls_msg_parser.c` (existing TLS fuzzer)

**Existing Coverage:**
- TLS message parsing fuzzed
- **Gap:** ASN.1 DER edge cases

**Known Issues:**
- Only accepts canonical DER encodings
- Rejects valid non-canonical certificates

**Enhancement Focus:**
1. **Non-Canonical DER:**
   - Indefinite length encodings
   - Long-form length encodings
   - BER (vs. strict DER) compliance

2. **Certificate Chain Validation:**
   - Self-signed certificates
   - Expired certificates
   - Invalid signature algorithms
   - Certificate chain depth = 10+

3. **Key Derivation Edge Cases:**
   - Label sizes = 64 bytes (boundary)
   - Context sizes > 64 (overflow test)

**Priority:** **MEDIUM - Week 5-6 of campaign**

---

## Fuzzing Infrastructure Recommendations

### Fuzzer Selection

| Fuzzer | Best For | Recommended Targets |
|--------|----------|---------------------|
| **AFL++** | General coverage-guided | Transaction parser, QUIC frames |
| **libFuzzer** | Tight integration, in-process | Bincode types, VM interpreter |
| **Honggfuzz** | Feedback-driven, multi-threaded | Shred reassembly, snapshot parsers |

### Fuzzing Environment Setup

```bash
# Install fuzzing tools
apt install afl++ honggfuzz clang

# Build with sanitizers
export CC=clang
export CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
make clean && make fuzz-all

# Run parallel fuzzing campaign
afl-fuzz -i corpus/vm/ -o findings/vm/ -M master -- ./fuzz_vm @@
afl-fuzz -i corpus/vm/ -o findings/vm/ -S slave1 -- ./fuzz_vm @@
afl-fuzz -i corpus/vm/ -o findings/vm/ -S slave2 -- ./fuzz_vm @@
```

### Corpus Management

**Initial Corpus Sources:**
1. **Mainnet Data:**
   - Capture live transactions, blocks, votes from mainnet
   - Export snapshot manifests from actual snapshots

2. **Unit Tests:**
   - Extract test vectors from existing unit tests
   - Convert to fuzzer input format

3. **Synthetic Generation:**
   - Create minimal valid inputs
   - Create maximal valid inputs
   - Create edge cases (boundaries, limits)

4. **Cross-Pollination:**
   - Share corpus between AFL++ instances
   - Merge findings from multiple fuzzers

### Continuous Fuzzing Infrastructure

```yaml
# CI/CD integration
fuzzing_job:
  schedule:
    - cron: "0 */6 * * *"  # Every 6 hours

  steps:
    - name: Run fuzzer suite
      run: |
        # 24-hour fuzzing runs
        timeout 24h make fuzz-all

    - name: Triage crashes
      run: |
        ./triage_crashes.sh findings/

    - name: Report findings
      run: |
        ./generate_report.sh > fuzzing_report.md
        gh issue create --title "Fuzzing Findings $(date)" \
                        --body-file fuzzing_report.md
```

---

## Fuzzing Campaign Timeline (Frankendancer-Focused)

### Phase 1: Critical Frankendancer Components (Weeks 1-2)

**Objective:** Build harnesses for unfuzzed critical Firedancer tiles

| Week | Target | Deliverable | Frankendancer Relevance |
|------|--------|-------------|------------------------|
| 1 | QUIC Frame Parser | All frame types coverage | ✅ CRITICAL - Front-line DoS defense |
| 1 | Bincode Types (expand) | Enhanced type coverage + corpus | ✅ HIGH - IPC between Firedancer/Agave |
| 2 | Shred Parser/FEC | Enhanced FEC + merkle fuzzing | ✅ HIGH - Block distribution |
| 2 | Transaction Parser | Edge case corpus expansion | ✅ MEDIUM - Already well-fuzzed |

**Expected Output:**
- 2 new fuzzing harnesses (QUIC frames, enhanced shred)
- 2 enhanced harnesses (bincode, transaction)
- Initial bug reports
- Baseline coverage metrics

---

### Phase 2: Supporting Components (Weeks 3-4)

**Objective:** Enhance existing fuzzers and supporting infrastructure

| Week | Target | Deliverable | Frankendancer Relevance |
|------|--------|-------------|------------------------|
| 3 | TLS/ASN.1 Edge Cases | Non-canonical DER tests | ✅ MEDIUM - TLS handshakes |
| 3 | Snapshot Parsers (enhance) | Improved corpus + structure-aware | ✅ MEDIUM - State restoration |
| 4 | Gossip Message Parser | Enhanced vote/peer fuzzing | ✅ LOW - Already well-fuzzed |

**Expected Output:**
- Corpus expansion for existing fuzzers
- Edge case coverage improvements
- TLS interoperability testing

---

### Phase 3: Continuous Fuzzing & Agave Components (Weeks 5+)

**Objective:** Long-term fuzzing infrastructure and Agave component analysis

| Week | Target | Deliverable | Notes |
|------|--------|-------------|-------|
| 5+ | Continuous Firedancer fuzzing | CI/CD integration, monitoring | All Firedancer components |
| 5+ | Agave sBPF VM analysis | Identify fuzzing strategy for Rust code | ⚠️ Requires Rust fuzzing tooling |
| 5+ | Agave CPI validation analysis | Identify fuzzing strategy for Rust code | ⚠️ Requires Rust fuzzing tooling |

**Expected Output:**
- Mature fuzzing infrastructure for Firedancer C components
- Analysis of Agave Rust component fuzzing requirements
- Continuous bug discovery
- Regression testing

**Note on Agave Components:** While sBPF VM and CPI validation are critical attack surfaces in Frankendancer, they're implemented in Rust (Agave). Fuzzing these requires:
1. Rust fuzzing tooling (cargo-fuzz, libFuzzer for Rust)
2. Coordination with Agave/Solana Labs fuzzing efforts
3. Different harness development approach

---

## Success Metrics (Frankendancer-Focused)

### Coverage Targets for Firedancer Components

| Component | Current Coverage | Target Coverage | Delta | Frankendancer Priority |
|-----------|------------------|-----------------|-------|----------------------|
| QUIC Frames | ~20% (transport params) | **80%** | +60% | ✅ CRITICAL |
| Bincode Types | ~40% (partial fuzzer) | **85%** | +45% | ✅ HIGH |
| Shred Parser/FEC | ~50% (basic tests) | **85%** | +35% | ✅ HIGH |
| TLS/ASN.1 | ~50% (basic fuzzer) | **75%** | +25% | ✅ MEDIUM |
| Transaction Parser | ~70% (existing fuzzer) | **85%** | +15% | ✅ MEDIUM |

**Measurement:** Use `llvm-cov` for line/branch coverage analysis

### Bug Discovery Goals

**Conservative Estimate (Frankendancer-focused, 10-week campaign):**
- **QUIC Frames:** 5-8 bugs (parsing, DoS, protocol violations)
- **Bincode Types:** 8-15 bugs (overflow, parsing, IPC edge cases)
- **Shred Parser/FEC:** 3-5 bugs (FEC decoding, merkle validation)
- **TLS/ASN.1:** 2-4 bugs (certificate parsing, handshake)
- **Transaction Parser:** 1-3 bugs (already well-tested)

**Total Expected:** 19-35 bugs across Firedancer components

### Excluded Components (Agave-Handled in Frankendancer)

The following critical components are NOT covered by this Firedancer-focused fuzzing campaign, as they're handled by Agave in Frankendancer:
- ⚠️ **sBPF VM Interpreter** - Agave Rust implementation
- ⚠️ **CPI Validation** - Agave Rust implementation
- ⚠️ **Consensus (Tower, Ghost, Replay)** - Agave Rust implementation
- ⚠️ **Equivocation Detection** - Not in Frankendancer (pure Firedancer only)

---

## Appendix A: Fuzzing Harness Templates

### Template 1: Simple Binary Parser

```c
#include "../../util/sanitize/fd_fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  putenv("FD_LOG_BACKTRACE=0");
  fd_boot(argc, argv);
  atexit(fd_halt);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_INPUT_SIZE) return 0;
  if (size > MAX_INPUT_SIZE) return 0;

  // Parse input
  my_struct_t parsed;
  int result = my_parser_parse(&parsed, data, size);

  // Validate invariants
  if (result == SUCCESS) {
    assert(validate_invariants(&parsed));
  }

  return 0;
}
```

### Template 2: State Machine Fuzzer

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Initialize state machine
  state_machine_t sm;
  state_machine_init(&sm);

  // Feed sequence of inputs
  ulong offset = 0;
  while (offset + INPUT_SIZE <= size) {
    input_t *input = (input_t*)(data + offset);

    // Transition state
    state_machine_step(&sm, input);

    // Verify state consistency
    assert(state_machine_is_valid(&sm));

    offset += INPUT_SIZE;
  }

  state_machine_destroy(&sm);
  return 0;
}
```

### Template 3: Round-Trip Encode/Decode

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Decode
  void *decoded = NULL;
  int err = decode(data, size, &decoded);

  if (err == SUCCESS) {
    // Re-encode
    uchar *encoded = NULL;
    size_t encoded_size = 0;
    encode(decoded, &encoded, &encoded_size);

    // Decode again
    void *decoded2 = NULL;
    decode(encoded, encoded_size, &decoded2);

    // Verify equality
    assert(objects_equal(decoded, decoded2));

    free(encoded);
    free(decoded2);
  }

  free(decoded);
  return 0;
}
```

---

## Appendix B: Fuzzer Build Commands

### AFL++ Build

```bash
# Build with AFL++ instrumentation
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-fsanitize=address -g"
export AFL_USE_ASAN=1

make clean
make fuzz_vm_interpreter

# Run fuzzer
afl-fuzz -i corpus/vm_initial/ \
         -o findings/vm/ \
         -m none \
         -t 1000 \
         -- ./fuzz_vm_interpreter @@
```

### libFuzzer Build

```bash
# Build with libFuzzer
export CC=clang
export CFLAGS="-fsanitize=fuzzer,address -g"

make clean
make fuzz_bincode_types

# Run fuzzer
./fuzz_bincode_types \
  -max_len=65536 \
  -timeout=10 \
  -jobs=16 \
  -workers=16 \
  corpus/bincode/
```

### Honggfuzz Build

```bash
# Build with Honggfuzz
export CC=hfuzz-clang
export CFLAGS="-fsanitize=address -g"

make clean
make fuzz_shred_reasm

# Run fuzzer
honggfuzz \
  -i corpus/shreds/ \
  -o findings/shreds/ \
  -n 16 \
  --tmout_sigvtalrm \
  --exit_upon_crash \
  -- ./fuzz_shred_reasm ___FILE___
```

---

## Appendix C: Known Fuzzing Challenges

### Challenge 1: VM Setup Complexity

**Issue:** sBPF VM requires extensive setup (memory regions, registers, syscalls)

**Solution:**
- Create helper function: `setup_vm_from_fuzz_input()`
- First N bytes = configuration, remaining = BPF bytecode
- Pre-allocate maximum memory regions

### Challenge 2: Consensus-Critical Validation

**Issue:** Some bugs only manifest in specific consensus contexts

**Solution:**
- Fuzz individual components in isolation
- Separate fuzzer for end-to-end transaction execution
- Differential testing against Agave validator

### Challenge 3: State Machine Sequences

**Issue:** Multi-input state machines (reassembly, equivocation) need sequences

**Solution:**
- Interpret fuzzer input as sequence (length-prefixed)
- Use AFL++ persistent mode for speed
- Save interesting intermediate states

### Challenge 4: Cryptographic Validity

**Issue:** Some inputs rejected early due to invalid signatures/hashes

**Solution:**
- Pre-compute valid signatures for fuzzer corpus
- Fuzz only non-cryptographic fields
- Separate fuzzer for signature verification logic

---

## Summary: Frankendancer vs. Pure Firedancer Fuzzing Scope

### Components Included in This Frankendancer-Focused Fuzzing Campaign

**Firedancer C Tiles (High Priority):**
1. ✅ **QUIC Frame Parser** - Network front-line, DoS defense
2. ✅ **Bincode Type Deserializers** - IPC between Firedancer/Agave
3. ✅ **Shred Parser/FEC Decoder** - Block distribution
4. ✅ **TLS/ASN.1 Parser** - Certificate validation, handshakes
5. ✅ **Transaction Parser** - Already well-tested, enhance corpus
6. ✅ **Signature Verification** - Already tested via existing harnesses
7. ✅ **Gossip Message Parser** - Already tested via existing harnesses

### Components Excluded (Not in Frankendancer or Handled by Agave)

**Pure Firedancer Only (Not Yet in Production):**
- ❌ **Equivocation Detection** (`src/choreo/eqvoc/`) - Only in pure Firedancer
- ❌ **Shred Reassembly State Machine** (`src/discof/reasm/`) - Only in pure Firedancer's `repair` tile
- ❌ **Tower Consensus** (`src/discof/tower/`) - Only in pure Firedancer
- ❌ **Ghost Fork Choice** (`src/choreo/ghost/`) - Only in pure Firedancer
- ❌ **Replay** (`src/discof/replay/`) - Only in pure Firedancer
- ❌ **Repair** (`src/discof/repair/`) - Only in pure Firedancer

**Handled by Agave in Frankendancer (Rust, Not C):**
- ⚠️ **sBPF VM Interpreter** - Critical but Agave-handled (requires Rust fuzzing)
- ⚠️ **CPI Validation** - Critical but Agave-handled (requires Rust fuzzing)
- ⚠️ **Bank/Execution** - Agave runtime
- ⚠️ **POH Generation** - Agave component

### Key Insight

This revised document focuses on fuzzing the **attack surface that Firedancer actually exposes in production Frankendancer deployments**: the networking layer (QUIC, TLS), block distribution (shreds), and IPC serialization (bincode). The consensus and execution components that remain in Agave require separate Rust-focused fuzzing efforts.

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-07 | Security Analysis | Initial comprehensive fuzzing target prioritization |
| 2.0 | 2025-11-11 | Security Analysis | Revised to focus on Frankendancer-only components, removed pure Firedancer targets |

---

**END OF FUZZING TARGETS DOCUMENT**

This document guides the fuzzing campaign prioritization for **Frankendancer** specifically, focusing on the Firedancer C components currently in production use. For pure Firedancer fuzzing (future work), see the removed sections in version 1.0.
