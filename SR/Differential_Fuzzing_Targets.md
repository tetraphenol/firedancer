# Differential Fuzzing Targets - Firedancer v1.0

Ranked assessment of all areas where Firedancer reimplements parsing/deserialization
logic that must match Agave's behavior. Divergences in these areas can cause bank hash
mismatches (HIGH), invalid block production (MEDIUM), or runtime conformance failures
(CRITICAL if funds affected).

## Scoring Criteria

| Factor | Weight | Description |
|--------|--------|-------------|
| Consensus Impact | 5x | Does divergence affect bank hash, account state, or fund balances? |
| Parser Complexity | 3x | Lines of hand-written parsing code, number of branches/edge cases |
| Existing Fuzz Coverage | 2x | Does a differential harness already exist? |
| Attack Surface | 2x | Can a remote attacker feed arbitrary input to this parser? |
| Hand-written vs Generated | 1x | Hand-written code has more divergence risk than codegen |

**Score range:** 0-50 (higher = more promising for differential fuzzing)

---

## Tier 1: Highest Priority (Score 40-50)

### 1. Vote State Deserialization (Score: 48)

**Files:** `src/flamenco/runtime/program/vote/fd_vote_codec.c` (1186 lines, 231 CHECK/READ macros)
`src/flamenco/runtime/program/vote/fd_vote_state_v3.c` (200 lines)

**Functions:**
- `fd_vote_state_versioned_deserialize()` - versioned vote state (V0.14.11, V1.14.11, Current)
- `fd_vote_instruction_deserialize()` - VoteInstruction enum (11+ variants)
- `fd_vote_decode_compact_update()` - CompactVoteStateUpdate
- `fd_vote_state_v3_deserialize()` - V3 vote state with `authorized_voters` TreeMap

**Why highest priority:**
- Entirely **hand-written** bincode deserialization (not auto-generated)
- **Consensus-critical**: vote state is hashed into the bank hash; any divergence in
  deserialized fields (authorized_voters, prior_voters, epoch_credits, last_timestamp)
  produces a different bank hash
- **Complex format**: versioned enum dispatch, variable-length arrays with `u64` counts,
  TreeMap deserialization (ordered key-value pairs), nested structs
- **No differential fuzz harness exists**
- **Attacker-controlled**: vote instructions arrive as on-chain transactions; vote state
  is read from account data during execution

**Specific divergence risks:**
- `authorized_voters` TreeMap: insertion order, duplicate key handling, capacity limits
- `prior_voters` circular buffer: wraparound semantics, empty buffer edge case
- `epoch_credits` vector: unbounded length from account data, truncation behavior
- CompactVoteStateUpdate: `lockout_offsets` reconstruction from deltas, `root` sentinel (ULONG_MAX)
- Version dispatch: what happens with unknown version discriminant (value > 3)?

---

### 2. BPF Loader Input Serialization (Score: 45)

**Files:** `src/flamenco/runtime/program/fd_bpf_loader_serialization.c` (829 lines)

**Functions:**
- `fd_bpf_loader_input_serialize_for_abiv0()` / `_abiv1()`
- `fd_bpf_loader_input_deserialize_for_abiv0()` / `_abiv1()`

**Why very high priority:**
- **Three distinct serialization modes** based on feature flags (`virtual_address_space_adjustments`,
  `account_data_direct_mapping`) - combinatorial complexity
- **Consensus-critical**: deserialization after BPF execution determines final account state;
  divergence = different account data committed to funk = bank hash mismatch
- **Complex layout**: padding/alignment rules, realloc regions, direct mapping fragmented regions,
  per-account metadata serialization order
- **No differential fuzz harness exists**
- **Hand-written** with intricate pointer arithmetic

**Specific divergence risks:**
- Padding calculation between accounts (16-byte alignment, gap fills)
- `MAX_PERMITTED_DATA_INCREASE` (10KiB) realloc region placement
- Direct mapping mode: fragmented region list construction, writable vs read-only permissions
- Deserialization after CPI: account data length changed by callee, realloc detection
- `is_duplicate` account handling in serialized layout (skipped but still occupies space)
- Read-only account memcmp: what exactly is compared (metadata + data, or just data)?

---

### 3. ELF/sBPF Loader (Score: 42)

**Files:** `src/ballet/sbpf/fd_sbpf_loader.c` (~2000 lines)

**Functions:**
- `fd_sbpf_elf_peek()` - ELF header/section validation
- `fd_sbpf_program_load()` - relocation processing, calldest registration, symbol table
- `fd_sbpf_lenient_elf_parse()` - dynamic table parsing (strict vs lenient modes)

**Why high priority:**
- **Hand-written** ELF parser tracking Agave's `rbpf` crate (v0.12.2 -> v0.14.4 migration in progress)
- **Consensus-critical**: determines which programs are valid, where code/data regions are,
  which functions exist. Invalid ELF accepted = executing garbage; valid ELF rejected = program
  deployment fails
- **Has fuzz harness** (`fuzz_sbpf_loader.c`) but unclear if it's differential vs Agave
- Complex SBPF version handling (V0, V2, V3) with different validation rules
- Relocation processing with multiple R_BPF_64_* types

**Specific divergence risks:**
- SBPF V3 vs V0/V2 validation differences (`.text` section handling, program header expectations)
- Calldest registration: murmur3 hash collision handling, bijective inverse
- Dynamic table entry ordering, duplicate DT_REL/DT_RELSZ entries
- Section header type validation (which section types are ignored vs rejected)
- `e_entry` validation: must point into `.text` section at instruction boundary

---

## Tier 2: High Priority (Score 30-39)

### 4. Auto-generated Bincode Type Decoders (Score: 38)

**Files:** `src/flamenco/types/fd_types.c` (3769 lines, auto-generated from `fd_types.json`)

**Key types:**
- `fd_system_program_instruction_t` - CreateAccount, Transfer, Assign, etc.
- `fd_bpf_upgradeable_loader_program_instruction_t` - Deploy, Upgrade, Write, Close
- `fd_nonce_state_versions_t` - nonce account deserialization
- `fd_address_lookup_table_state_t` - ALT deserialization
- `fd_stake_state_v2_t` - stake account deserialization

**Why high priority:**
- **Auto-generated** from JSON schema, which reduces divergence risk vs hand-written
- But the **code generator** (`gen_stubs.py`) is itself hand-written and could have bugs
- These types are used at transaction execution time with attacker-controlled data
- Divergence in system program instruction parsing = wrong instruction executed = fund loss
- **No dedicated differential fuzz harness** for individual type decoders

**Specific divergence risks:**
- Enum discriminant handling: Agave uses `bincode::deserialize` which rejects unknown variants;
  does `fd_types.c` do the same?
- String deserialization: length-prefixed, what's the max length? UTF-8 validation?
- Option<T>: `None` vs `Some(T)` encoding (0/1 prefix byte)
- Vec<T>: `u64` length prefix, maximum allowed length, empty vector handling

---

### 5. Gossip Message Deserialization (Score: 35)

**Files:** `src/flamenco/gossip/fd_gossip_message.c` (~700 lines)

**Functions:** `fd_gossip_message_deserialize()`

**Why high priority:**
- **Hand-written** custom bincode parser (not using fd_types framework)
- **Has differential fuzz harness** (`fuzz_gossip_message_deserialize.c`) and a
  `differential_fuzzer.patch` suggesting active differential testing
- **Network-facing**: directly receives UDP packets from any peer
- Divergence could cause: gossip state desync (validator sees different cluster state),
  vote propagation failure, ContactInfo corruption

**Specific divergence risks:**
- ContactInfo V2 serde: socket table construction, address sanitization rules
- CRDS value signature validation ordering vs deserialization
- Bloom filter parameter acceptance: Agave's exact bounds on `num_bits_set`, `keys`
- Prune message: `destination` and `origin` field ordering, wallclock validation

---

### 6. Transaction Parser (Score: 34)

**Files:** `src/ballet/txn/fd_txn_parse.c`

**Functions:** `fd_txn_parse_core()`

**Why high priority:**
- **Has fuzz harness** (`fuzz_txn_parse.c`) but unclear if differential
- **Network-facing**: every transaction goes through this parser
- Divergence could cause: valid transaction rejected (liveness) or invalid transaction
  accepted (consensus violation)
- compact-u16 encoding edge cases, versioned transaction handling

**Specific divergence risks:**
- compact-u16 encoding: 3-byte encoding for values 16384-65535, canonical encoding enforcement
- Versioned transaction: V0 message vs legacy message disambiguation
- Address lookup table index validation: indices >= table length
- Signature count limits, account address count limits

---

### 7. Snapshot Manifest Parser (Score: 32)

**Files:** `src/discof/restore/utils/fd_ssmanifest_parser.c` (~500 lines)

**Functions:** `fd_ssmanifest_parser_consume()`

**Why moderate-high priority:**
- **Hand-written** state machine parser for bincode snapshot manifest
- **Has fuzz harness** (`fuzz_ssmanifest_parser.c`)
- **Consensus-critical at boot**: if manifest is parsed incorrectly, validator starts with
  wrong state (wrong epoch, wrong slot, wrong capitalization)
- Input comes from snapshot download (potentially MITM'd without cert pinning)

**Specific divergence risks:**
- 80+ state transitions for deeply nested manifest structure
- Vote account deserialization embedded in manifest (stakes)
- `UnusedAccounts` field: skip behavior must match Agave exactly
- Float fields (inflation parameters): IEEE 754 representation in bincode

---

## Tier 3: Medium Priority (Score 20-29)

### 8. Compute Budget Program Parser (Pack Tile Fast Path) (Score: 28)

**Files:** `src/disco/pack/fd_compute_budget_program.h`

**Functions:** `fd_compute_budget_program_parse()`

- **Has fuzz harness** (`fuzz_compute_budget_program_parse.c`)
- Simple 4-byte enum tag dispatch, low complexity
- Divergence affects block packing (compute budget estimation) but not bank hash directly
- Used in pack tile hot path - must match Agave's compute budget processing

### 9. Shred Parser (Score: 27)

**Files:** `src/ballet/shred/fd_shred.c`

**Functions:** `fd_shred_parse()`

- **Has fuzz harness** (`fuzz_shred_parse.c`)
- Divergence could cause: valid shred rejected (repair/retransmit failure) or invalid
  shred accepted (equivocation detection bypass)
- Variant field validation (data vs coding shred type bits)

### 10. Repair Protocol Serde (Score: 25)

**Files:** `src/discof/repair/fd_repair.c`

- **Partial fuzz coverage** (`fuzz_repair_serde.c` covers ping/pong only)
- Packed struct interpretation for ShredRepair, HighestShred, Orphan requests
- Divergence could cause repair protocol failure (missing shreds)

### 11. Slot Delta / Status Cache Parser (Score: 24)

**Files:** `src/discof/restore/utils/fd_slot_delta_parser.c`

- **Has fuzz harness** (`fuzz_slot_delta_parser.c`)
- Parsed from snapshot; affects status cache state at boot
- Divergence could allow transaction replay or block double-processing

### 12. Genesis Parser (Score: 22)

**Files:** `src/flamenco/genesis/fd_genesis_parse.c`

- **Has fuzz harness** (`fuzz_genesis_parse.c`)
- Only processed once at bootstrap; input from trusted source (genesis file)
- Divergence could cause wrong initial state

### 13. IP Echo Client (Score: 20)

**Files:** `src/discof/ipecho/fd_ipecho_client.c`

- **Has fuzz harness** (`fuzz_ipecho_client.c`)
- Simple binary response format
- Divergence could cause wrong self-reported IP address

---

## Tier 4: Lower Priority (Score < 20)

### 14. Base58 Encoding/Decoding (Score: 18)
- Has differential harness (`fuzz_base58_roundtrip.c`)
- Used in logging/display, not consensus-critical path

### 15. QUIC/TLS Parsers (Score: 15)
- Independent implementation (not matching Agave - Agave uses Quinn/rustls)
- RFC conformance matters, not Agave conformance
- Already well-fuzzed

### 16. HTTP/H2/HPACK Parsers (Score: 12)
- Independent implementation, not consensus-critical
- Already well-fuzzed

### 17. JSON Parser (cJSON) (Score: 10)
- Third-party library, only used in RPC (not consensus path)
- Standard, battle-tested parser

### 18. TOML Parser (Score: 5)
- Config files only, not untrusted input
- Header says "not hardened against untrusted input"

---

## Recommended Differential Fuzzing Campaign

### Immediate High-Value Targets (no existing differential harness)

1. **Vote codec** - Write a harness that feeds the same bincode to both
   `fd_vote_state_versioned_deserialize()` and Agave's `VoteState::deserialize()`,
   comparing all output fields

2. **BPF loader serialization** - Write a harness that serializes the same account set
   under all three modes, then deserializes post-execution state, comparing against Agave's
   `serialize_parameters()` / `deserialize_parameters()`

3. **Auto-generated bincode decoders** - Write a generic differential harness that tests
   each `fd_*_decode()` function against Rust `bincode::deserialize::<T>()` for the
   corresponding type

### Enhance Existing Harnesses

4. **ELF loader** - Confirm `fuzz_sbpf_loader.c` is differential (compares against rbpf);
   if not, add Agave comparison

5. **Gossip deserializer** - The `differential_fuzzer.patch` suggests this was attempted;
   verify it's active and covers all message types

6. **Transaction parser** - Confirm `fuzz_txn_parse.c` compares against Agave's
   `VersionedTransaction::sanitize()`
