# VM-001: Binary Search Integer Underflow in Memory Region Lookup

## Severity
**HIGH** (downgraded from CRITICAL due to existing mitigation at primary call site, but fundamental bug exists)

## Summary
The sBPF VM's binary search function for memory region lookup (`fd_vm_get_input_mem_region_idx`) has an integer underflow vulnerability when `input_mem_regions_cnt` is zero. While the current primary call site has a defensive check, the function itself is inherently unsafe and violates defense-in-depth principles.

## Affected Components
- `src/flamenco/vm/fd_vm_private.h:296-310` (vulnerable function)
- `src/flamenco/vm/syscall/fd_vm_syscall_macros.h:205-212` (unprotected macro)

## Technical Details

### Vulnerability Mechanism

```c
// src/flamenco/vm/fd_vm_private.h:296-310
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  uint left  = 0U;
  uint right = vm->input_mem_regions_cnt - 1U;  // LINE 298: UNDERFLOW
  uint mid   = 0U;

  while( left<right ) {
    mid = (left+right) / 2U;
    // LINE 303: Out-of-bounds array access when cnt==0
    if( offset>=vm->input_mem_regions[ mid ].vaddr_offset+
                vm->input_mem_regions[ mid ].address_space_reserved ) {
      left = mid + 1U;
    } else {
      right = mid;
    }
  }
  return left;
}
```

**When `vm->input_mem_regions_cnt == 0`:**
1. Line 298: `right = 0U - 1U = 0xFFFFFFFF` (UINT_MAX = 4,294,967,295)
2. Loop executes: `left (0) < right (4294967295)` → true
3. Line 302: `mid = (0 + 4294967295) / 2 = 2,147,483,647`
4. Line 303: Accesses `vm->input_mem_regions[2147483647]` → **OUT OF BOUNDS**

### Current Mitigation (Partial)

The main call site has a check:

```c
// src/flamenco/vm/fd_vm_private.h:390-392
if( FD_UNLIKELY( vm->input_mem_regions_cnt==0 ) ) {
  return sentinel;
}
ulong region_idx = fd_vm_get_input_mem_region_idx( vm, offset );
```

However, this is insufficient because:

1. **Unsafe API Design**: Function should be self-contained and safe
2. **Macro Usage**: The macro `FD_VM_MEM_HADDR_AND_REGION_IDX_FROM_INPUT_REGION_CHECKED` calls the function without checking cnt
3. **Future Risk**: New code may call this function incorrectly
4. **Comment Misleading**: Line 290-294 says "This function makes NO guarantees about the input being a valid input region offset" but doesn't mention the cnt requirement

### Can This Be Exploited?

To exploit this, an attacker would need to:

1. **Trigger VM execution with zero memory regions**: This is likely prevented by VM initialization logic
2. **Exploit via macro**: If `FD_VM_MEM_HADDR_AND_REGION_IDX_FROM_INPUT_REGION_CHECKED` is used without checking cnt
3. **Future code path**: New syscalls or VM operations that call this function

**Feasibility**: Currently LOW due to existing checks, but this represents a **latent vulnerability** that could become exploitable through:
- Code refactoring that removes the defensive check
- New features that call this function
- Syscall implementations using the unprotected macro

### Potential Impact

If triggered:
- **Memory Disclosure**: Reading vm->input_mem_regions[huge_index] exposes arbitrary memory
- **Crash/DoS**: Segmentation fault from invalid memory access
- **Memory Corruption**: If the index happens to land in writable memory (unlikely but possible)

## Proof of Concept

```c
#include "fd_vm_private.h"

int test_underflow() {
    fd_vm_t vm = {0};
    vm.input_mem_regions_cnt = 0;  // Trigger condition
    vm.input_mem_regions = NULL;

    // This will underflow and access vm.input_mem_regions[2147483647]
    ulong idx = fd_vm_get_input_mem_region_idx(&vm, 0x1000);

    printf("Returned index: %lu\n", idx);
    // Expected: Safe handling
    // Actual: Undefined behavior / crash

    return 0;
}
```

Expected behavior:
```
Segmentation fault (core dumped)
```

or information disclosure if the out-of-bounds address happens to be mapped memory.

## Root Cause Analysis

The root cause is **missing input validation** in the binary search function. The function assumes `cnt >= 1` but doesn't enforce this precondition.

**Design Flaw**: The function's contract (documented in lines 290-294) doesn't specify the precondition that cnt must be non-zero. This violates the principle of least surprise and creates a maintenance hazard.

## Recommended Mitigations

### Immediate Fix (Required)

Add a precondition check to the function:

```c
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  // CRITICAL: Function requires cnt > 0
  if( FD_UNLIKELY( vm->input_mem_regions_cnt == 0 ) ) {
    return 0;  // Return 0 as a safe default (caller must validate)
  }

  uint left  = 0U;
  uint right = vm->input_mem_regions_cnt - 1U;
  uint mid   = 0U;

  while( left<right ) {
    mid = (left+right) / 2U;
    if( offset>=vm->input_mem_regions[ mid ].vaddr_offset+
                vm->input_mem_regions[ mid ].address_space_reserved ) {
      left = mid + 1U;
    } else {
      right = mid;
    }
  }
  return left;
}
```

### Alternative Fix (More Defensive)

Use a checked subtraction:

```c
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  uint cnt = vm->input_mem_regions_cnt;
  if( FD_UNLIKELY( cnt == 0 ) ) return 0;

  uint left  = 0U;
  uint right = cnt - 1U;  // Safe now that we've checked cnt > 0
  // ... rest of function
}
```

### Documentation Fix

Update the function comment to explicitly state the precondition:

```c
/* fd_vm_get_input_mem_region_idx returns the index into the input memory
   region array with the largest region offset that is <= the offset that
   is passed in.

   PRECONDITION: vm->input_mem_regions_cnt MUST be > 0.
                 Behavior is undefined if cnt == 0 (integer underflow).

   This function makes NO guarantees about the input being a valid input
   region offset; the caller is responsible for safely handling it. */
```

### Static Analysis

Add compile-time assertion:

```c
// In the function or caller
FD_STATIC_ASSERT( sizeof(uint) == 4, "Assumes uint is 32-bit for underflow" );
```

And enable compiler warnings:
```bash
-Wtype-limits -Wsign-conversion -Wconversion
```

## Verification

### Test Case

```c
void test_vm_zero_regions() {
    fd_vm_t vm = {0};
    vm.input_mem_regions_cnt = 0;
    vm.input_mem_regions = NULL;

    // Should NOT crash or access invalid memory
    ulong idx = fd_vm_get_input_mem_region_idx(&vm, 0);

    // Verify safe behavior
    assert(idx == 0);  // Or some safe sentinel value
}
```

### Static Analysis

Run Coverity/CodeQL with rules:
- Integer overflow/underflow detection
- Array bounds checking
- Unsigned arithmetic wraparound

## Related Issues

This is related to but distinct from:
- **VM-002**: Memory region overlap detection
- **VM-004**: Instruction pointer validation

All three involve bounds checking in the VM.

## Status
- **Discovered**: 2025-11-08
- **Severity**: HIGH (not CRITICAL due to existing mitigation)
- **Exploitability**: LOW (currently mitigated at call site)
- **Risk**: MEDIUM (latent vulnerability, defense-in-depth violation)
- **Priority**: HIGH (fix to prevent future exploitation)

## References

1. **CWE-191**: Integer Underflow (Wrap or Wraparound)
   - https://cwe.mitre.org/data/definitions/191.html

2. **CERT C Secure Coding**: INT30-C
   - "Ensure that unsigned integer operations do not wrap"

3. **Binary Search Edge Cases**:
   - Classic pitfall when handling empty arrays
   - Similar bug in Java's Arrays.binarySearch (fixed in Java 6)

## Conclusion

While this vulnerability is currently mitigated by defensive checks at the call site, it represents a **code quality and maintainability issue** that should be fixed. The function violates the principle that library functions should be safe to call without requiring callers to check preconditions.

**Recommendation**: Apply the immediate fix (add cnt==0 check to function) to eliminate this latent vulnerability before it can be exploited through future code changes.
