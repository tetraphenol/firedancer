# Feature Gate Divergence Risk Review

Focused on 5 recent/risky feature gates in the Firedancer v1.0 codebase.
Scope: consensus-critical divergence risks only.

---

## 1. enable_sbpf_v3_deployment_and_execution

**Feature ID:** `0x0f1fc5fdd7907244` (pubkey: `5cC3foj77CWun58pC51ebHFUWavHWKarWyR5UUik7dnC`)

### Usage Locations

| File | Function/Context |
|------|-----------------|
| `src/flamenco/progcache/fd_prog_load.c:102` | `fd_prog_versions()` - sets `max_sbpf_version` to `FD_SBPF_V3` |

### Gated Behavior

When **on**: Programs can be deployed and executed with SBPF V3 bytecode. This enables a cascade of sub-features defined in `fd_vm_private.h:99-105`:
- `FD_VM_SBPF_STATIC_SYSCALLS` (SIMD-0178) - syscall dispatch via static table
- `FD_VM_SBPF_ENABLE_STRICTER_ELF_HEADERS` (SIMD-0189) - stricter ELF validation
- `FD_VM_SBPF_ENABLE_LOWER_RODATA_VADDR` (SIMD-0189) - rodata mapped at vaddr 0
- `FD_VM_SBPF_ENABLE_JMP32` (SIMD-0377) - 32-bit jump instructions
- `FD_VM_SBPF_CALLX_USES_DST_REG` (SIMD-0377) - callx register convention change

When **off**: Max SBPF version is V2 (or V1/V0 depending on other features).

### Complexity: HIGH

This is not a simple flag check. It unlocks an entirely new bytecode version with:
- New opcode map in the interpreter jump table (`fd_vm_interp_jump_table.c:162-193`) - 22+ new opcodes
- New validation rules in `fd_vm_validate()` (`fd_vm.c:229-340`) - different opcode validity per version
- Changed memory layout - rodata at vaddr 0 instead of `0x100000000` (`fd_vm_private.h:209`)
- Changed ELF loading behavior in `fd_sbpf_loader.h:377-389`
- Static syscall dispatch (`fd_vm_interp_jump_table.c:162`)

### Divergence Risk: HIGH

The SBPF V3 interpreter is a complete re-implementation of instruction semantics for JMP32 opcodes. The validation map in `fd_vm_validate()` has complex version-dependent overrides where later overrides can shadow earlier ones (e.g., PQR opcodes vs JMP32 opcodes at lines 276-340). The `OVERRIDE_WITH_FALLBACK` macro in the jump table handles the mutual exclusivity of PQR (V2) and JMP32 (V3) opcodes, but any error in opcode mapping would produce a consensus divergence.

Key risk areas:
- Opcode validation map ordering - if PQR and JMP32 overrides interact incorrectly
- `CALLX_USES_DST_REG` vs `CALLX_USES_SRC_REG` (V3 vs V2) - register encoding changes
- `ENABLE_LOWER_RODATA_VADDR` changes the virtual memory layout fundamentally
- Static syscall resolution at V3 changes how syscall hash lookups work

### Notes
- No `hardcode_for_fuzzing` flag on this feature (unlike v1/v2), meaning it is not fuzz-tested as aggressively
- The feature_map.json entry has no `cleaned_up` or `hardcode_for_fuzzing` flag

---

## 2. virtual_address_space_adjustments

**Feature ID:** `0xce2f9f1c3aeba901` (pubkey: `EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF`)

### Usage Locations

| File | Function/Context |
|------|-----------------|
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:132,405` | Checked via `FD_FEATURE_ACTIVE_BANK`, passed to serialization and VM init |
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:213,470` | Passed to `fd_vm_init()` |
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:541` | Controls access violation error code mapping |
| `src/flamenco/runtime/program/fd_bpf_loader_serialization.c:159,170,182` | `write_account()` - controls serialization mode (Mode 1 vs Mode 2/3) |
| `src/flamenco/runtime/program/fd_bpf_loader_serialization.c:430-556` | `fd_bpf_loader_input_deserialize_for_abiv1()` - deserialization logic |
| `src/flamenco/vm/fd_vm.h:220,318` | Stored in VM struct, passed to VM init |
| `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:147-153` | CPI account update logic |
| `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:436-457,577,627` | CPI caller account handling |
| `src/flamenco/progcache/fd_progcache_rec.c:175` | Program cache validation |
| `src/flamenco/runtime/fd_core_bpf_migration.c:413` | Core BPF migration |

### Gated Behavior

When **on** (Mode 2 or Mode 3 depending on `account_data_direct_mapping`):
- Serialization splits the input region into per-account metadata and data regions (fragmented memory map)
- Each account gets separate metadata and data memory regions with independent write permissions
- Address space reserved per account calculated differently
- Deserialization uses region-aware logic rather than single-buffer offset calculation
- CPI updates use region-based account tracking with `ref_to_len_in_vm` pointers
- Access violations return more specific error codes based on `segv_vaddr`

When **off** (Mode 1):
- Single contiguous buffer for all accounts
- Everything writable in the input region
- Simple offset-based deserialization

### Complexity: VERY HIGH

This is the most complex feature gate in the codebase. It fundamentally changes:
- How the VM's input memory region is structured (fragmented vs contiguous)
- The serialization format (3 distinct modes documented in `fd_bpf_loader_serialization.c:38-113`)
- The deserialization path with different data copy/compare semantics
- CPI behavior for account data propagation
- Error reporting for memory access violations

The serialization code has hand-written buffer arithmetic throughout (`write_account()` at line 150+), with region size calculations, alignment handling, and address space reservation logic that differs between modes.

### Divergence Risk: HIGH

- The deserialization function `fd_bpf_loader_input_deserialize_for_abiv1()` has a complex 3-way branch at lines 495-535 (`!virtual_address_space_adjustments` / `!direct_mapping && can_data_be_changed` / `data_len != post_len`)
- Buffer advancement logic differs: `start += MAX_PERMITTED_DATA_INCREASE + pre_len + alignment_offset` (Mode 1/2) vs `start += FD_BPF_ALIGN_OF_U128` (Mode 3)
- The CPI code has multiple conditional paths based on `virtual_address_space_adjustments && direct_mapping` combinations
- Alignment padding behavior differs between modes (line 232-248): Mode 2 aligns data content, Mode 3 aligns region start

---

## 3. syscall_parameter_address_restrictions

**Feature ID:** `0x14bfb27001414cc4` (pubkey: `CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE`)

### Usage Locations

| File | Function/Context |
|------|-----------------|
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:131,404` | Feature check at BPF loader entry |
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:212,469` | Passed to `fd_vm_init()` |
| `src/flamenco/vm/fd_vm.h:219,317` | Stored in VM struct |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:28` | `sol_get_clock_sysvar` |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:64` | `sol_get_epoch_schedule_sysvar` |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:107` | `sol_get_rent_sysvar` |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:144` | `sol_get_last_restart_slot_sysvar` |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:189` | `sol_get_sysvar` |
| `src/flamenco/vm/syscall/fd_vm_syscall_runtime.c:603` | `sol_get_epoch_rewards_sysvar` |
| `src/flamenco/progcache/fd_progcache_rec.c:174` | Program cache validation |
| `src/flamenco/runtime/fd_core_bpf_migration.c:412` | Core BPF migration |

### Gated Behavior

When **on**: Syscalls that write sysvar data reject output pointers that point into the input region (`vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START`). Returns `FD_VM_SYSCALL_ERR_INVALID_POINTER`.

When **off**: No address restriction on output pointers - programs can write sysvar data anywhere in the VM address space, including into the input region.

### Complexity: LOW

Simple address range check: `out_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START`. Same pattern repeated identically in 6 syscall functions. The check is straightforward.

### Divergence Risk: LOW

The implementation is a simple vaddr comparison, repeated identically across all affected syscalls. The risk is low as long as `FD_VM_MEM_MAP_INPUT_REGION_START` matches Agave's constant (which it does - defined in `fd_vm_base.h`).

One minor concern: the check is only applied to 6 sysvar syscalls. If Agave applies this restriction to additional syscalls not covered here, that would be a divergence. Should verify completeness against Agave's implementation.

---

## 4. account_data_direct_mapping

**Feature ID:** `0x35639bb5e67799a9` (pubkey: `7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz`)

### Usage Locations

| File | Function/Context |
|------|-----------------|
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:130,403` | Feature check, stored as `direct_mapping` |
| `src/flamenco/runtime/program/fd_bpf_loader_program.c:211,468` | Passed to `fd_vm_init()` |
| `src/flamenco/runtime/program/fd_bpf_loader_serialization.c:160,198,217,222,233,243` | `write_account()` serialization |
| `src/flamenco/runtime/program/fd_bpf_loader_serialization.c:518,538` | Deserialization logic |
| `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:162,179,453,577,627` | CPI data propagation |
| `src/flamenco/progcache/fd_progcache_rec.c:173` | Program cache validation |
| `src/flamenco/runtime/fd_core_bpf_migration.c:411` | Core BPF migration |

**Note:** `bpf_account_data_direct_mapping` (feature ID `0x28b4db1b1a8a9d90`) is an older, separate feature defined in the feature set. It is disabled in genesis configuration alongside `account_data_direct_mapping` but is NOT referenced in any runtime code - only in feature definitions and genesis config. This suggests the older feature was superseded by the newer one.

### Gated Behavior

When **on** (Mode 3, requires `virtual_address_space_adjustments`):
- Account data is NOT copied into the serialization buffer. Instead, the data memory region points directly to the borrowed account's staging area.
- No memcpy during serialization for account data (line 222-224)
- No memcpy during deserialization - data modified in-place
- In CPI, `serialized_data` is NULL and `serialized_data_len` is 0 (line 453-456)
- Alignment padding is `FD_BPF_ALIGN_OF_U128` fixed instead of data-length-dependent (line 245-247)
- Region start is aligned differently with `serialized_params_start` adjustment (line 247)

When **off** (Mode 2 if `virtual_address_space_adjustments` is on):
- Account data is memcpy'd into the serialization buffer
- CPI tracks `serialized_data` pointer into the buffer
- Data must be copied back during deserialization

### Complexity: HIGH

The feature interacts with `virtual_address_space_adjustments` to form Mode 3. The interaction matrix creates three distinct behavioral modes. Key areas of hand-written logic:

1. **Serialization (`write_account`)**: Different buffer management depending on `direct_mapping`:
   - Line 198-204: memcpy vs no-op
   - Line 209-210: address_space_reserved calculation
   - Line 217-224: region pointing to buffer copy vs direct account data
   - Line 233-248: alignment padding semantics differ significantly

2. **CPI (`fd_vm_syscall_cpi_common.c`)**: Account data propagation differs:
   - Line 162: zero-memory on shrink only when `!direct_mapping`
   - Line 179: copy-back only when `!direct_mapping`
   - Line 453-457: serialized_data is NULL vs buffer pointer
   - Line 577,627: data resize/copy-back skipped when both features active

3. **Deserialization**: Skip `set_data_from_slice` when `direct_mapping`, only do `set_data_length` if lengths differ (line 529-534)

### Divergence Risk: HIGH

The `write_account` alignment padding at line 243-247 is particularly risky:
```
fd_memset( *serialized_params, 0, FD_BPF_ALIGN_OF_U128 );
*serialized_params       += FD_BPF_ALIGN_OF_U128;
*serialized_params_start += fd_ulong_sat_sub( FD_BPF_ALIGN_OF_U128, align_offset );
```
The `serialized_params_start` adjustment with `fd_ulong_sat_sub` is hand-written arithmetic that determines region boundaries. Any mismatch with Agave's alignment calculation would cause region vaddr offsets to be wrong, leading to memory translation errors and consensus divergence.

The CPI code path where `virtual_address_space_adjustments && direct_mapping` is checked in multiple places with different combinations - some check both, some check only one. Any inconsistency in which combination is checked could cause divergence.

---

## 5. delay_commission_updates

**Feature ID:** `0xf5434d796d0f975a` (pubkey: `76dHtohc2s5dR3ahJyBxs7eJJVipFkaPdih9CLgTTb4B`)

### Usage Locations

| File | Function/Context |
|------|-----------------|
| `src/flamenco/runtime/program/fd_vote_program.c:1628` | Feature check at vote program entry |
| `src/flamenco/runtime/program/fd_vote_program.c:1846` | Passed to `update_commission()` as `disable_commission_update_rule` |
| `src/flamenco/runtime/program/fd_vote_program.c:954,966,969` | `update_commission()` - controls commission update timing rule |
| `src/flamenco/runtime/program/fd_vote_program.c:2233` | `update_commission_bps` - requires this feature |
| `src/flamenco/rewards/fd_rewards.c:994,1002` | Rewards recalculation - commission source selection |
| `src/flamenco/stakes/fd_stakes.c:583-584` | Epoch stake computation - commission source selection |
| `src/discof/restore/utils/fd_ssmsg.h:484` | Documentation reference for snapshot restore |

### Gated Behavior

**Vote Program (`update_commission`):**
When **on**: The parameter `disable_commission_update_rule` is true, meaning commission *decreases* are allowed at any time in the epoch. Only commission *increases* are restricted to the first half of the epoch (line 969: `commission > fd_vsv_get_commission(...)`).

When **off**: All commission updates (increases and decreases) are restricted to the first half of the epoch via `is_commission_update_allowed()`.

**Rewards Calculation (`fd_rewards.c`):**
When **on**: Use the t-2 epoch commission (with t-3 override if available) for reward splitting.
- Line 994-995: `vote_ele->commission = stake_t_2>0UL ? commission_t_2 : commission_t_1`
- Line 1002-1009: Override with t-3 commission from `fd_bank_snapshot_commission_t_3()`

When **off**: Use current epoch (t-1) commission: `vote_ele->commission = commission_t_1`

**Stakes (`fd_stakes.c`):**
When **on**: Commission selection cascade: t-3 > t-2 > t-1 (line 584: `exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1)`)

When **off**: Use t-1 commission directly.

### Complexity: MEDIUM

The vote program logic is a simple conditional, but the rewards/stakes logic involves looking up commission values from multiple historical epochs. This requires:
- `fd_vote_stakes_query()` with t-1 and t-2 stakes/commission
- `fd_vote_stakes_query_t_2()` for t-3 commission
- `fd_bank_snapshot_commission_t_3()` bank state for snapshot restore path

### Divergence Risk: MEDIUM-HIGH

Key risk areas:

1. **Commission cascade logic in `fd_stakes.c:583-584`**: The fallback chain `t-3 > t-2 > t-1` must exactly match Agave's. Note the different logic between `fd_stakes.c` and `fd_rewards.c`:
   - `fd_stakes.c`: `exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1)`
   - `fd_rewards.c`: `stake_t_2>0UL ? commission_t_2 : commission_t_1` (then overridden by t-3 in a separate loop)
   These two paths should produce identical results but use different code structures. The rewards path first picks t-2 commission based on stake existence, then overrides with t-3 commission from a separate data source. Any discrepancy in the t-3 commission data would cause reward amounts to diverge.

2. **`update_commission` parameter inversion**: The feature is named `delay_commission_updates` but is passed to `update_commission()` as `disable_commission_update_rule`. The logic inverts it: `enforce_commission_update_rule = !disable_commission_update_rule`. When the feature is active AND the new commission is higher than current, the rule is enforced. This double-negation pattern is error-prone.

3. **Snapshot restore path**: The t-3 commission stashing in `fd_rewards.c:1002-1009` loads from `fd_bank_snapshot_commission_t_3()` bank state. If this state isn't correctly populated during snapshot loading, rewards recalculation would use wrong commission values, causing bank hash mismatch.

---

## Summary Risk Matrix

| Feature | Complexity | Divergence Risk | Code Paths Affected | Hand-written Parsing |
|---------|-----------|-----------------|--------------------|--------------------|
| enable_sbpf_v3_deployment_and_execution | High | High | ELF loader, validator, interpreter, memory map | Opcode tables, ELF parsing |
| virtual_address_space_adjustments | Very High | High | Serialization, deserialization, CPI, error handling | Buffer arithmetic, region layout |
| syscall_parameter_address_restrictions | Low | Low | 6 sysvar syscalls | None |
| account_data_direct_mapping | High | High | Serialization, deserialization, CPI | Alignment padding, region offset calc |
| delay_commission_updates | Medium | Medium-High | Vote program, rewards, stakes | Commission cascade lookups |

## Priority Audit Targets

1. **fd_bpf_loader_serialization.c `write_account()`** - The alignment padding divergence between Mode 2 and Mode 3 (lines 233-248) is the highest-risk hand-written arithmetic in this review.

2. **fd_vm_syscall_cpi_common.c** - The conditional matrix of `virtual_address_space_adjustments` x `direct_mapping` creates 4 possible behavioral states but only 3 are meaningful. Verify all branch conditions match Agave.

3. **fd_vm_interp_jump_table.c** - The `OVERRIDE_WITH_FALLBACK` macro handling mutual exclusivity of PQR and JMP32 opcodes. Any opcode mapping error would be a consensus divergence on V3 programs.

4. **fd_rewards.c / fd_stakes.c commission cascade** - The two different code paths for computing the delayed commission must produce identical results. The different data sources (bank state vs vote_stakes queries) need careful verification.

5. **Completeness of `syscall_parameter_address_restrictions`** - Verify the 6 syscalls with the restriction match Agave's list exactly. Missing a syscall would allow input-region writes that Agave blocks.
