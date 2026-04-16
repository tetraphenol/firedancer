# LOW: sBPF VM Undefined Behavior on Wide Shift Operations

**CVE**: TBD
**Severity**: Low (depends on Agave behavior)
**Component**: sBPF VM Interpreter
**Location**: `src/flamenco/vm/fd_vm_interp_core.c:972,985,989,1003`
**Affected Versions**: Current Firedancer main branch

## Summary

The sBPF VM interpreter performs shift operations without validating that shift amounts are within valid ranges, resulting in undefined behavior when shift amount >= bit-width. This could cause non-deterministic execution compared to Agave if the undefined behavior manifests differently between implementations.

## Technical Details

C/C++ standards specify that shifting a value by >= its bit-width is undefined behavior. The sBPF VM has multiple shift instructions that don't validate shift amounts:

### Affected Instructions

**1. ARSH_IMM (0xc4)** - Line 972:
```c
FD_VM_INTERP_INSTR_BEGIN(0xc4) /* FD_SBPF_OP_ARSH_IMM */
  reg[ dst ] = (ulong)(uint)( (int)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
FD_VM_INTERP_INSTR_END;
```
- 32-bit arithmetic right shift by immediate
- `imm` is not validated to be < 32
- If `imm >= 32`, behavior is undefined

**2. ARSH64_IMM (0xc7)** - Line 985:
```c
FD_VM_INTERP_INSTR_BEGIN(0xc7) /* FD_SBPF_OP_ARSH64_IMM */
  reg[ dst ] = (ulong)( (long)reg_dst >> imm ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
FD_VM_INTERP_INSTR_END;
```
- 64-bit arithmetic right shift by immediate
- `imm` not validated to be < 64

**3. ARSH_REG (0xcc)** - Line 989:
```c
FD_VM_INTERP_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
  reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (uint)reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
FD_VM_INTERP_INSTR_END;
```
- 32-bit arithmetic right shift by register value
- `reg_src` not masked to 5 bits (0-31 range)

**4. ARSH64_REG (0xcf)** - Line 1003:
```c
FD_VM_INTERP_INSTR_BEGIN(0xcf) /* FD_SBPF_OP_ARSH64_REG */
  reg[ dst ] = (ulong)( (long)reg_dst >> reg_src ); /* FIXME: WIDE SHIFTS, STRICT SIGN EXTENSION */
FD_VM_INTERP_INSTR_END;
```
- 64-bit arithmetic right shift by register value
- `reg_src` not masked to 6 bits (0-63 range)

Similar issues likely exist for logical shift operations (LSH, RSH).

## Proof of Concept

### PoC 1: Immediate Shift Overflow

```rust
// Solana BPF assembly
mov r1, 0x80000000    // Load value with sign bit set
arsh r1, 32           // Shift by 32 (undefined behavior for 32-bit)
exit
```

Expected behavior: Depends on Agave implementation
- If Agave masks `imm & 0x1F` → shift by 0, result = 0x80000000
- If Agave uses full `imm` → undefined, possibly 0x00000000 or 0x80000000
- Firedancer: Currently undefined

### PoC 2: Register Shift Overflow

```rust
mov r1, 0xFFFFFFFFFFFFFFFF
mov r2, 100                   // Shift amount > 64
arsh64 r1, r2                 // Undefined behavior
exit
```

Possible outcomes:
- Some compilers: shift amount is modulo bit-width (100 % 64 = 36)
- Some compilers: result is 0 or unchanged
- Some compilers: actual shift by 100 (implementation-defined)

### PoC 3: Consensus Divergence Attack

```rust
// Deploy program that uses wide shifts
mov r1, <transaction_hash>
mov r2, 65
rsh64 r1, r2                 // Result depends on undefined behavior
jeq r1, 0, accept
exit                         // reject
accept:
  // Perform state change
```

If Firedancer and Agave have different undefined behavior:
- Agave accepts transaction, modifies state
- Firedancer rejects transaction
- Consensus fork!

## Impact

**Severity Assessment**:

- **If Agave DOES validate/mask shift amounts**: **CRITICAL** - Consensus divergence
- **If Agave has SAME undefined behavior**: **LOW** - Both implementations non-deterministic
- **If undefined behavior is consistent**: **INFO** - No practical impact

**Potential Impacts**:

1. **Consensus Divergence**: If implementations disagree on shift results, same transaction produces different state
2. **Non-Determinism**: Undefined behavior may vary between:
   - Different CPU architectures (x86 vs ARM)
   - Different compiler versions
   - Different optimization levels
   - Release vs debug builds

3. **Limited Exploitability**:
   - Attacker must deploy program with wide shifts
   - Must know how both implementations handle undefined behavior
   - Requires program execution, can't be triggered via transaction structure alone

## Investigation Required

**Critical Next Steps**:

1. **Check Agave Implementation**:
   ```bash
   # Check Solana RBPF implementation
   grep -r "arsh" agave/
   # Look for shift masking like: shift_amt & 0x3F
   ```

2. **Test Cross-Implementation Determinism**:
   - Deploy test program to devnet with wide shifts
   - Compare results between Agave and Firedancer
   - Document any divergence

3. **Check BPF Specification**:
   - Review eBPF/sBPF specification for shift behavior
   - Determine if wide shifts are explicitly defined or forbidden

## Remediation

### Option 1: Mask Shift Amounts (Recommended)

```c
FD_VM_INTERP_INSTR_BEGIN(0xc4) /* FD_SBPF_OP_ARSH_IMM */
  reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (imm & 0x1F) );  // Mask to 0-31
FD_VM_INTERP_INSTR_END;

FD_VM_INTERP_INSTR_BEGIN(0xc7) /* FD_SBPF_OP_ARSH64_IMM */
  reg[ dst ] = (ulong)( (long)reg_dst >> (imm & 0x3F) );  // Mask to 0-63
FD_VM_INTERP_INSTR_END;

FD_VM_INTERP_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
  reg[ dst ] = (ulong)(uint)( (int)reg_dst >> ((uint)reg_src & 0x1FU) );
FD_VM_INTERP_INSTR_END;

FD_VM_INTERP_INSTR_BEGIN(0xcf) /* FD_SBPF_OP_ARSH64_REG */
  reg[ dst ] = (ulong)( (long)reg_dst >> (reg_src & 0x3FUL) );
FD_VM_INTERP_INSTR_END;
```

### Option 2: Validate and Fault

```c
FD_VM_INTERP_INSTR_BEGIN(0xcc) /* FD_SBPF_OP_ARSH_REG */
  if( FD_UNLIKELY( reg_src >= 32UL ) ) {
    // Fault: invalid shift amount
    goto sigsegv;  // or appropriate fault handler
  }
  reg[ dst ] = (ulong)(uint)( (int)reg_dst >> (uint)reg_src );
FD_VM_INTERP_INSTR_END;
```

### Option 3: Match Agave Exactly

- Reverse-engineer Agave's behavior via testing
- Replicate exact behavior (even if undefined)
- Ensures determinism but may propagate bugs

## Testing

```c
// Test case for wide shift detection
void test_wide_shifts(void) {
  fd_vm_t vm = /* ... initialize VM ... */;

  // Test 32-bit shift by 32
  uint8_t prog1[] = {
    0xb7, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  // mov r1, 0x80000000
    0xc4, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,  // arsh r1, 32
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   // exit
  };

  uint64_t result = fd_vm_exec( &vm, prog1, sizeof(prog1) );
  printf("32-bit shift by 32: r1 = 0x%lx\n", vm.reg[1]);

  // Test 64-bit shift by 100
  uint8_t prog2[] = {
    0xb7, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,  // mov r1, -1
    0xb7, 0x02, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00,  // mov r2, 100
    0xcf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // arsh64 r1, r2
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00   // exit
  };

  result = fd_vm_exec( &vm, prog2, sizeof(prog2) );
  printf("64-bit shift by 100: r1 = 0x%lx\n", vm.reg[1]);
}
```

## References

- sBPF VM interpreter: `src/flamenco/vm/fd_vm_interp_core.c`
- C standard on undefined behavior: ISO/IEC 9899:2018, 6.5.7
- eBPF specification: (if available)
- Related: CWE-758 (Reliance on Undefined Behavior)
