# VM-001: Complete Examples of fd_vm_init and fd_vm_validate Patterns

## Overview

This document provides comprehensive working examples of how to properly initialize and validate the Firedancer sBPF VM (`fd_vm_init` and `fd_vm_validate`). These patterns were extracted from actual test files in the codebase.

## Key Insight: Calldests Parameter

The critical issue when `calldests` is passed as `NULL`:

**From fd_vm.c (lines 616-620):**
```
/* We do support calldests==NULL for tests that do not require
   indirect calls (calldests). However, if the sBPF version supports
   stricter ELF headers (v3+), calldests must be provided or be NULL.
   SBPF v3+ no longer needs calldests, so we enforce it to be NULL. */
if( FD_UNLIKELY( calldests && fd_sbpf_enable_stricter_elf_headers_enabled( sbpf_version ) ) ) {
  // ERROR: calldests provided for v3+, which doesn't support it
}
```

**Rules for calldests parameter:**
- **v0/v1/v2**: Can use `NULL` for calldests (indirect calls not validated)
- **v3+**: MUST use `NULL` for calldests (stricter validation enforced)
- If you have actual indirect calls in v0-v2, calldests must be a proper bitset

## Complete Working Example #1: Simple Test (test_vm_interp.c)

**Source:** `/home/greg/Firedancer/firedancer/src/flamenco/vm/test_vm_interp.c` lines 35-88

This is the simplest working pattern - no input data, no syscalls, just basic VM execution:

```c
static void
test_program_success( char *                test_case_name,
                      ulong                 expected_result,
                      ulong const *         text,
                      ulong                 text_cnt,
                      fd_sbpf_syscalls_t *  syscalls,
                      fd_exec_instr_ctx_t * instr_ctx ) {

  /* Step 1: Create SHA context */
  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );

  /* Step 2: Create and join VM */
  fd_vm_t _vm[1];
  fd_vm_t * vm = fd_vm_join( fd_vm_new( _vm ) );
  FD_TEST( vm );

  /* Step 3: Initialize VM with NULL calldests (OK for v0/v1/v2) */
  int vm_ok = !!fd_vm_init(
      /* vm                                   */ vm,
      /* instr_ctx                            */ instr_ctx,
      /* heap_max                             */ FD_VM_HEAP_DEFAULT,
      /* entry_cu                             */ FD_VM_COMPUTE_UNIT_LIMIT,
      /* rodata                               */ (uchar *)text,
      /* rodata_sz                            */ 8UL*text_cnt,
      /* text                                 */ text,
      /* text_cnt                             */ text_cnt,
      /* text_off                             */ 0UL,
      /* text_sz                              */ 8UL*text_cnt,
      /* entry_pc                             */ 0UL,
      /* calldests                            */ NULL,  // OK: NULL for tests
      /* sbpf_version                         */ TEST_VM_DEFAULT_SBPF_VERSION,
      /* syscalls                             */ syscalls,
      /* trace                                */ NULL,
      /* sha                                  */ sha,
      /* mem_regions                          */ NULL,  // No input data
      /* mem_regions_cnt                      */ 0UL,
      /* mem_regions_accs                     */ NULL,
      /* is_deprecated                        */ 0,
      /* direct mapping                       */ FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot, &instr_ctx->txn_ctx->features, account_data_direct_mapping ),
      /* stricter_abi_and_runtime_constraints */ FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot, &instr_ctx->txn_ctx->features, stricter_abi_and_runtime_constraints ),
      /* dump_syscall_to_pb */ 0
  );
  FD_TEST( vm_ok );

  /* Step 4: Setup VM execution state BEFORE validation */
  vm->pc        = vm->entry_pc;
  vm->ic        = 0UL;
  vm->cu        = vm->entry_cu;
  vm->frame_cnt = 0UL;
  vm->heap_sz   = 0UL;
  fd_vm_mem_cfg( vm );

  /* Step 5: Validate the program */
  int err = fd_vm_validate( vm );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "validation failed: %i-%s", err, fd_vm_strerror( err ) ));

  /* Step 6: Execute the program */
  err = fd_vm_exec( vm );
  
  FD_TEST( vm->reg[0]==expected_result );
}
```

**Key requirements fulfilled:**
1. VM memory allocated and joined
2. All required parameters passed to `fd_vm_init`
3. Execution state initialized (pc, ic, cu, frame_cnt, heap_sz)
4. `fd_vm_mem_cfg()` called
5. `fd_vm_validate()` called before execution
6. `fd_vm_exec()` called to run program

## Complete Working Example #2: With Calldests and Syscalls (test_vm_instr.c)

**Source:** `/home/greg/Firedancer/firedancer/src/flamenco/vm/test_vm_instr.c` lines 436-488

This example shows how to properly allocate and use calldests:

```c
/* Step 1: Create calldests bitset */
fd_sbpf_calldests_t * calldests =
    fd_sbpf_calldests_join(
    fd_sbpf_calldests_new(
    aligned_alloc( fd_sbpf_calldests_align(), fd_sbpf_calldests_footprint( text_cnt ) ),
    text_cnt ) );

/* Step 2: Create syscalls table */
fd_sbpf_syscalls_t * syscalls =
    fd_sbpf_syscalls_join(
    fd_sbpf_syscalls_new(
    aligned_alloc( fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) ) );

/* Step 3: Create execution context */
fd_exec_instr_ctx_t instr_ctx[1];
fd_exec_txn_ctx_t   txn_ctx[1];
test_vm_minimal_exec_instr_ctx( instr_ctx, txn_ctx );

/* Step 4: Create input memory regions */
fd_vm_input_region_t input_region[32];
input_region[0] = (fd_vm_input_region_t){
  .vaddr_offset           = 0UL,
  .haddr                  = (ulong)input_copy,
  .region_sz              = input->input_sz,
  .address_space_reserved = input->input_sz,
  .is_writable            = 1U,
};

/* Step 5: Initialize VM with calldests */
int vm_ok = !!fd_vm_init(
    /* vm                                   */ vm,
    /* instr_ctx                            */ instr_ctx,
    /* heap_max                             */ 0UL,
    /* entry_cu                             */ 100UL,
    /* rodata                               */ (uchar const *)text,
    /* rodata_sz                            */ text_cnt * sizeof(ulong),
    /* text                                 */ text,
    /* text_cnt                             */ text_cnt,
    /* text_off                             */ 0UL,
    /* text_sz                              */ text_cnt * sizeof(ulong),
    /* entry_pc                             */ 0UL,
    /* calldests                            */ calldests,  // ACTUAL calldests
    /* sbpf_version                         */ sbpf_version,
    /* syscalls                             */ syscalls,
    /* trace                                */ NULL,
    /* sha                                  */ NULL,
    /* mem_regions                          */ input_region,
    /* mem_regions_cnt                      */ input->region_boundary_cnt ? input->region_boundary_cnt : 1,
    /* mem_regions_accs                     */ NULL,
    /* is_deprecated                        */ 0,
    /* direct mapping                       */ FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot, &instr_ctx->txn_ctx->features, account_data_direct_mapping ),
    /* stricter_abi_and_runtime_constraints */ FD_FEATURE_ACTIVE( instr_ctx->txn_ctx->slot, &instr_ctx->txn_ctx->features, stricter_abi_and_runtime_constraints ),
    /* dump_syscall_to_pb */ 0
);
assert( vm_ok );

/* Step 6: Setup execution state */
for( uint i=0; i<REG_CNT; i++ ) {
  vm->reg[i] = input->reg[i];
}

/* Step 7: Validate and execute */
if( fd_vm_validate( vm ) != FD_VM_SUCCESS ) {
  // Handle validation failure
  return;
}

if( fd_vm_exec_notrace( vm ) != FD_VM_SUCCESS ) {
  // Handle execution failure
  return;
}

/* Step 8: Cleanup */
free( fd_sbpf_syscalls_delete ( fd_sbpf_syscalls_leave ( syscalls  ) ) );
free( fd_sbpf_calldests_delete( fd_sbpf_calldests_leave( calldests ) ) );
```

**Key differences from Example #1:**
1. Explicit calldests allocation with `fd_sbpf_calldests_new()`
2. Explicit syscalls table creation with `fd_sbpf_syscalls_new()`
3. Input memory regions configured for program input data
4. Proper cleanup of allocated objects

## Complete Working Example #3: Realistic Configuration (fd_vm_harness.c)

**Source:** `/home/greg/Firedancer/firedancer/src/flamenco/runtime/tests/fd_vm_harness.c` lines 190-286

This example shows realistic program setup with complex initialization:

```c
/* Step 1: Setup calldests from optional whitelist */
ulong max_pc = (rodata_sz + 7) / 8;
ulong calldests_footprint = fd_sbpf_calldests_footprint( max_pc );
void * calldests_mem = fd_spad_alloc_check( spad, fd_sbpf_calldests_align(), calldests_footprint );
ulong * calldests = fd_sbpf_calldests_join( fd_sbpf_calldests_new( calldests_mem, max_pc ) );

/* Step 2: Copy call whitelist if provided */
if( input->vm_ctx.call_whitelist && input->vm_ctx.call_whitelist->size > 0 ) {
  memcpy( calldests, input->vm_ctx.call_whitelist->bytes, input->vm_ctx.call_whitelist->size );
  /* Mask off bits beyond max_pc */
  ulong mask = (1UL << (max_pc % 64)) - 1UL;
  if ( max_pc % 64 != 0) {
    calldests[ max_pc / 64 ] &= mask;
  }
}

/* Step 3: For v3+, ensure entry point is enabled */
ulong entry_pc = fd_ulong_min( input->vm_ctx.entry_pc, rodata_sz / 8UL - 1UL );
if( input->vm_ctx.sbpf_version >= FD_SBPF_V3 ) {
  calldests[ entry_pc / 64UL ] |= ( 1UL << ( entry_pc % 64UL ) );
}

/* Step 4: Setup syscalls table with registered syscalls */
fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_new( 
  fd_spad_alloc_check( spad, fd_sbpf_syscalls_align(), fd_sbpf_syscalls_footprint() ) );
fd_vm_syscall_register_slot( syscalls,
                             instr_ctx->txn_ctx->slot,
                             &instr_ctx->txn_ctx->features,
                             0 );

/* Step 5: Register custom syscall implementations if needed */
for( ulong i=0; i< fd_sbpf_syscalls_slot_cnt(); i++ ){
  if( !fd_sbpf_syscalls_key_inval( syscalls[i].key ) ) {
    syscalls[i].func = custom_syscall_handler;
  }
}

/* Step 6: Create VM instance */
fd_vm_t * vm = fd_vm_join( fd_vm_new( fd_spad_alloc_check( spad, fd_vm_align(), fd_vm_footprint() ) ) );

/* Step 7: Initialize VM */
fd_vm_init(
  vm,
  instr_ctx,
  input->vm_ctx.heap_max,
  input->has_instr_ctx ? input->instr_ctx.cu_avail : 0,
  rodata,
  rodata_sz,
  (ulong *) rodata,
  rodata_sz / 8,
  0,                        /* text_off */
  rodata_sz,                /* text_sz */
  entry_pc,
  calldests,
  input->vm_ctx.sbpf_version,
  syscalls,
  trace,                    /* Can be NULL if no tracing */
  NULL,                     /* sha */
  input_mem_regions,
  input_mem_regions_cnt,
  acc_region_metas,
  is_deprecated,
  direct_mapping,
  stricter_abi_and_runtime_constraints,
  0
);

/* Step 8: Setup register state from input */
vm->reg[0]  = input->vm_ctx.r0;
vm->reg[2]  = input->vm_ctx.r2;
/* ... setup all other registers ... */

/* Step 9: Validate the VM */
if( fd_vm_validate( vm ) != FD_VM_SUCCESS ) {
  effects->error = -2;
  return;
}

/* Step 10: Execute the program */
int exec_res = fd_vm_exec( vm );
```

**Advanced features shown:**
1. Calldests properly sized and masked
2. v3+ entry point special handling
3. Syscall registration and customization
4. Complex memory region setup
5. Register initialization from input
6. Validation with error handling

## Example #4: Fuzzer Pattern (Minimal Setup)

**Source:** `/home/greg/Firedancer/firedancer/SR/fuzz/sBPF/fuzz_sbpf_vm.c` lines 231-290

Minimal setup for fuzzing performance:

```c
/* Initialize VM (failure is expected for some inputs) */
int vm_ok = !!fd_vm_init(
  vm,
  instr_ctx,
  config.heap_max,
  config.entry_cu,
  (uchar *)text,
  8UL * text_cnt,
  text,
  text_cnt,
  0UL,
  8UL * text_cnt,
  config.entry_pc,
  NULL,                     /* Calldests: NULL for fuzzing */
  config.sbpf_version,
  NULL,                     /* Syscalls: NULL for fuzzing */
  NULL,                     /* Trace: disabled */
  sha,
  regions,                  /* Memory regions from config */
  regions_cnt,
  NULL,
  0,                        /* is_deprecated */
  config.enable_direct_mapping & 1,
  0,
  0
);

if (!vm_ok) {
  return 0;  /* Skip invalid inputs */
}

/* Setup execution state */
vm->pc = vm->entry_pc;
vm->ic = 0UL;
vm->cu = vm->entry_cu;
vm->frame_cnt = 0UL;
vm->heap_sz = 0UL;
fd_vm_mem_cfg(vm);

/* Validate */
if (fd_vm_validate(vm) != FD_VM_SUCCESS) {
  return 0;  /* Skip invalid programs */
}

/* Execute */
int exec_err = fd_vm_exec(vm);
```

## Memory Regions Setup Pattern

When your program needs input data:

```c
fd_vm_input_region_t input_region[32];

/* Setup region 0 */
input_region[0] = (fd_vm_input_region_t){
  .vaddr_offset           = 0UL,              /* Starts at VM addr 0 */
  .haddr                  = (ulong)data,      /* Host pointer to data */
  .region_sz              = data_size,        /* Size of data */
  .address_space_reserved = data_size,        /* Reserved space */
  .is_writable            = 1U,               /* Can be modified */
  .acc_region_meta_idx    = 0,                /* Account metadata index */
};

/* If you have multiple regions, set them up similarly:
   input_region[1] = {...vaddr_offset = data_size, ...};
   etc
*/

/* Pass to fd_vm_init */
fd_vm_init(
  /* ... other params ... */
  input_region,    /* mem_regions */
  1,               /* mem_regions_cnt - number of regions */
  NULL,            /* mem_regions_accs - account metadata (can be NULL) */
  /* ... */
);
```

## Execution Context Setup Pattern

```c
fd_exec_instr_ctx_t instr_ctx[1];
fd_exec_txn_ctx_t   txn_ctx[1];

/* Initialize context (use helper function from test_vm_util.h) */
test_vm_minimal_exec_instr_ctx( instr_ctx, txn_ctx );

/* Or manually setup if helper unavailable:
 * memset(instr_ctx, 0, sizeof(*instr_ctx));
 * memset(txn_ctx, 0, sizeof(*txn_ctx));
 * instr_ctx->txn_ctx = txn_ctx;
 * txn_ctx->slot = <slot_number>;
 * // initialize features as needed
 */

/* Use FD_FEATURE_ACTIVE to check features */
int direct_mapping = FD_FEATURE_ACTIVE( 
  instr_ctx->txn_ctx->slot, 
  &instr_ctx->txn_ctx->features, 
  account_data_direct_mapping 
);
```

## Validation Rules Checklist

Before calling `fd_vm_exec()`, ensure:

1. [ ] `fd_vm_init()` succeeded (returns non-zero)
2. [ ] Execution state initialized:
   - [ ] `vm->pc = vm->entry_pc`
   - [ ] `vm->ic = 0UL`
   - [ ] `vm->cu = vm->entry_cu`
   - [ ] `vm->frame_cnt = 0UL`
   - [ ] `vm->heap_sz = 0UL`
3. [ ] `fd_vm_mem_cfg()` called
4. [ ] All register state initialized if needed
5. [ ] `fd_vm_validate()` returns `FD_VM_SUCCESS`
6. [ ] Program version matches calldests setup:
   - v3+ MUST use NULL calldests
   - v0-v2 can use NULL or bitset

## Common Pitfalls

1. **Calldests with v3+**: Causes immediate validation failure
2. **Not setting execution state**: VM runs with uninitialized state
3. **Skipping fd_vm_mem_cfg()**: Memory regions not properly configured
4. **NULL memory regions with programs needing input**: Data access faults
5. **Uninitialized instr_ctx**: Missing execution context
6. **Wrong feature flags**: Behavior differs from intended setup

## Summary

Working VM initialization requires:
- Proper VM memory allocation and joining
- Correct calldests setup (NULL for v3+, bitset or NULL for v0-v2)
- Execution context initialization
- All execution state fields set before validation
- Successful validation before execution
- Proper cleanup of allocated resources

Use these patterns as templates for your own VM initialization code.
