# ALT-001: Address Lookup Table Decoder Accepts Data Agave Rejects

**Severity:** Invalid (not reachable in Firedancer runtime)
**Component:** `src/flamenco/types/fd_types.c` (auto-generated `fd_address_lookup_table_state_decode`)

## Description

Firedancer's auto-generated bincode decoder for `fd_address_lookup_table_state` accepts
inputs that Agave's `AddressLookupTable::deserialize` rejects. Differential fuzzing found
3,183 mismatches, all in the direction `fd=1 agave=0`.

## Why It's Invalid

The divergent standalone decoder is not used in the Firedancer runtime. The actual runtime
path in `fd_alut_interp_next()` (`src/flamenco/runtime/fd_alut.h:175-263`) uses a hybrid
approach that matches Agave:

1. Calls the bincode decoder with `buf_sz = FD_LOOKUP_TABLE_META_SIZE` (56) to decode only
   the discriminant + metadata header (line 206)
2. Reads addresses as raw 32-byte entries at offset 56 via pointer arithmetic (lines 222-223)
   - no bincode length prefix, matching Agave's `bytemuck::try_cast_slice`

Additionally, pre-validation guards reject all inputs that triggered fuzzer mismatches:
- `alut_data_sz < 56` rejected (line 199) - catches all sub-56-byte inputs
- `discriminant != 1` rejected (line 211) - catches Uninitialized (0) case
- `(alut_data_sz - 56) % 32 != 0` rejected (line 217) - catches misaligned data
- Owner must be the ALT program (line 194)

The `fd_address_lookup_table_t` struct contains only `fd_lookup_table_meta_t meta` - there
is no addresses vector in the type definition, so no bincode length prefix is ever used for
addresses in any code path.

On-chain ALT accounts are exclusively written by the AddressLookupTable program in the
correct format. An attacker cannot create malformed ALT accounts.

The only other call site (`src/discoh/bank/fd_bank_abi.c:367`) is Frankendancer-only code,
out of scope for this contest.

## Found By

Differential fuzzing: `fuzz_bincode_types_diff` (fd_address_lookup_table_state_decode vs
Agave AddressLookupTable::deserialize).
