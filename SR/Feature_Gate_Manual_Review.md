# REVIEW-001: Feature Gate Divergence Manual Review

## Areas Reviewed

### Area 1: BPF Serialization Alignment Arithmetic (fd_bpf_loader_serialization.c)

**Result: No divergence found.**

Reviewed `write_account()` lines 150-255 across all three serialization modes. The alignment padding logic matches Agave's `serialization.rs` `write_account()` (lines 128-190).

Key findings:
- `FD_BPF_ALIGN_OF_U128` (8) matches Agave's `BPF_ALIGN_OF_U128` (8)
- `fd_ulong_align_up(dlen, 8) - dlen` is semantically equivalent to Rust's `(dlen as *const u8).align_offset(8)` - both compute `(8 - (dlen % 8)) % 8`, yielding values in [0, 7]
- Mode 3 (direct mapping): `serialized_params_start += fd_ulong_sat_sub(FD_BPF_ALIGN_OF_U128, align_offset)` matches Agave's `self.region_start += BPF_ALIGN_OF_U128.saturating_sub(align_offset)`
- The `fd_ulong_sat_sub` saturation can never trigger because `align_offset` is always in [0, 7] and `FD_BPF_ALIGN_OF_U128` is 8
- The `serialized_params` advancement by `FD_BPF_ALIGN_OF_U128` matches Agave's `fill_write(BPF_ALIGN_OF_U128, 0)`

### Area 2: Commission Cascade in Rewards/Stakes

**Result: Potential minor divergence identified, assessed as non-exploitable.**

Two structurally different code paths set the commission for `delay_commission_updates`:

- `fd_stakes.c:584`: `exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1)` - uses `fd_vote_stakes_query_t_2()` which returns `found && stake > 0`
- `fd_rewards.c:995-1008`: First `stake_t_2 > 0 ? commission_t_2 : commission_t_1`, then overrides with t-3 from bank snapshot

These two paths handle different situations:
- `fd_stakes.c` runs at normal epoch boundaries
- `fd_rewards.c` runs during snapshot recovery

The conditions `exists_t_2` (fd_stakes.c) and `stake_t_2 > 0` (fd_rewards.c) are equivalent because `fd_vote_stakes_query_t_1()` returns `found && *stake_out > 0`.

The two paths produce equivalent results for the same inputs because the snapshot commission_t_3 data is populated from the same epoch_stakes that feed the vote_stakes queries.

Observation: Agave uses `VoteAccounts::get()` which succeeds for vote accounts with zero delegated stake (all vote accounts are in the map regardless of stake). Firedancer's `fd_vote_stakes_query_t_2()` filters by `stake > 0`. This could theoretically cause a divergence for a vote account that existed at t-3 with zero delegated stake but had delegations at distribution time. However, this requires: (1) the vote account to have been present in vote_stakes with zero stake at the right epoch, (2) a commission change between epochs, and (3) new delegations arriving. The practical impact is limited because Firedancer seeds its stake_accum_map from existing vote_stakes entries and the scenario requires a very specific sequence of delegation changes. This observation is noted for thoroughness but does not warrant a separate finding.

### Area 3: Syscall Address Restrictions Completeness

**Result: No divergence found. Coverage matches.**

Firedancer syscalls with `syscall_parameter_address_restrictions && out_vaddr >= FD_VM_MEM_MAP_INPUT_REGION_START` check:
1. `fd_vm_syscall_sol_get_clock_sysvar` (line 27)
2. `fd_vm_syscall_sol_get_epoch_schedule_sysvar` (line 63)
3. `fd_vm_syscall_sol_get_rent_sysvar` (line 107)
4. `fd_vm_syscall_sol_get_last_restart_slot_sysvar` (line 144)
5. `fd_vm_syscall_sol_get_sysvar` (line 189)
6. `fd_vm_syscall_sol_get_epoch_rewards_sysvar` (line 603)

Agave syscalls with equivalent check (via `get_sysvar` helper or direct):
1. `SyscallGetClockSysvar`
2. `SyscallGetEpochScheduleSysvar`
3. `SyscallGetEpochRewardsSysvar`
4. `SyscallGetFeesSysvar` (deprecated - not registered in Firedancer, acceptable)
5. `SyscallGetRentSysvar`
6. `SyscallGetLastRestartSlotSysvar`
7. `SyscallGetSysvar`

CPI restrictions in `fd_vm_syscall_cpi_common.c` match Agave's `cpi.rs`:
- account_infos array bounds check (line 826-830)
- key/owner/lamports/data pointer checks via `VM_SYSCALL_CPI_CHECK_ACCOUNT_INFO_POINTER_FIELD_MAX_54`
- lamports Rc<RefCell> pointer check (line 353)
- data_len_vaddr >= MM_INPUT_START check (line 405)
- serialized_data length vs address_space_reserved check (line 426-437)
- CU consumption for data length (line 478-480)

`SyscallGetFeesSysvar` is not registered in Firedancer (the `sol_get_fees_sysvar` symbol is absent from the syscall registration in `fd_vm_syscall.c`). This is acceptable because the Fees sysvar is deprecated and the feature `disable_fees_sysvar` has been active on mainnet.

## Files Reviewed

- `/home/user/FiredancerAC/firedancer/src/flamenco/runtime/program/fd_bpf_loader_serialization.c` (lines 150-426)
- `/home/user/FiredancerAC/firedancer/agave/program-runtime/src/serialization.rs` (lines 128-190)
- `/home/user/FiredancerAC/firedancer/src/flamenco/rewards/fd_rewards.c` (lines 958-1010)
- `/home/user/FiredancerAC/firedancer/src/flamenco/stakes/fd_stakes.c` (lines 530-610)
- `/home/user/FiredancerAC/firedancer/src/flamenco/stakes/fd_vote_stakes.c` (lines 410-490)
- `/home/user/FiredancerAC/firedancer/src/flamenco/vm/syscall/fd_vm_syscall_runtime.c` (full file)
- `/home/user/FiredancerAC/firedancer/src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c` (lines 298-504, 815-842)
- `/home/user/FiredancerAC/firedancer/src/flamenco/vm/syscall/fd_vm_syscall_cpi.c` (lines 515-521)
- `/home/user/FiredancerAC/firedancer/agave/syscalls/src/sysvar.rs` (full file)
- `/home/user/FiredancerAC/firedancer/agave/program-runtime/src/cpi.rs` (relevant sections)
- `/home/user/FiredancerAC/firedancer/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs`
- `/home/user/FiredancerAC/firedancer/agave/runtime/src/stakes.rs`
