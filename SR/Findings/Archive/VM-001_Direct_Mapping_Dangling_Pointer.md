# VM-001: Direct Mapping Dangling Pointer After CPI Account Realloc

**Category**: VM / Memory Safety
**Severity**: HIGH
**Component**: CPI Implementation (`fd_vm_syscall_cpi_common.c`)
**Status**: Confirmed (requires direct_mapping feature enabled)

## Summary

In direct mapping mode, the CPI caller account tracking stores `ref_to_len_in_vm` as a raw host pointer to the length field in VM memory. When an inner CPI call reallocates account data (changing the underlying buffer), this pointer becomes dangling. Subsequent dereference in the outer CPI's account update reads/writes freed or reallocated memory — a use-after-free condition.

## Technical Details

### Pointer Storage (fd_vm_syscall_cpi_common.c:476)
```c
ulong * data_len = FD_VM_MEM_HADDR_ST( vm, data_len_vaddr, 1UL, sizeof(ulong) );
caller_account->ref_to_len_in_vm = data_len;  // Raw host pointer stored
```

### Direct Mapping Mode (lines 451-454)
```c
if( vm->stricter_abi_and_runtime_constraints && vm->direct_mapping ) {
  caller_account->serialized_data     = NULL;
  caller_account->serialized_data_len = 0UL;
}
```

In this mode, account data is NOT copied — the VM's memory regions point directly to the account's data buffer.

### Dangling Dereference (lines 551-553, 622-623)
```c
ulong prev_len = *caller_account->ref_to_len_in_vm;  // READ through potentially dangling pointer
ulong post_len = fd_txn_account_get_data_len( callee_acc );
// ...
*caller_account->ref_to_len_in_vm = post_len;  // WRITE through potentially dangling pointer
```

### Region Update Doesn't Fix It (fd_vm_syscall_cpi.c:304-341)
```c
fd_vm_cpi_update_caller_account_region( ... ) {
  region->region_sz = (uint)fd_borrowed_account_get_data_len( borrowed_account );
  // Updates region_sz but NOT the physical address if buffer was relocated
}
```

### Attack Scenario

1. Outer program borrows account A, `ref_to_len_in_vm` points to length field in VM memory
2. Outer calls inner CPI which calls `sol_realloc()` on account A with a larger size
3. Account A's data buffer is reallocated to a new address
4. Inner CPI returns to outer program
5. Outer CPI's `ref_to_len_in_vm` still points to the OLD length field location
6. Dereference reads/writes memory at the old (now-freed) address

## Impact

- **Use-after-free**: Read/write to freed memory
- **Memory corruption**: Write of `post_len` to arbitrary freed location
- **Potential sandbox escape**: If freed memory is reused for a different account, length field corruption affects another account's data boundary

## Prerequisites

- `vm->direct_mapping` must be enabled (feature-gated)
- `vm->stricter_abi_and_runtime_constraints` must be true
- These features may not yet be active on mainnet

## Remediation

After CPI realloc, recompute `ref_to_len_in_vm` from the current VM address space:
```c
// After CPI returns, re-resolve the pointer:
caller_account->ref_to_len_in_vm = FD_VM_MEM_HADDR_ST( vm, data_len_vaddr, 1UL, sizeof(ulong) );
```

## References

- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:451-476` (pointer storage)
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:551-553` (dangling read)
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi_common.c:622-623` (dangling write)
- `src/flamenco/vm/syscall/fd_vm_syscall_cpi.c:304-341` (region update)
- `src/flamenco/vm/fd_vm_cpi.h:167-176` (caller_account struct)
