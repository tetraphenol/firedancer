# MEDIUM: Snapshot Manifest Fields Injected Without Semantic Validation

**Category**: SNAPSHOT
**Severity**: Medium
**Component**: Snapshot Loading (Restore)
**Location**: `src/discof/restore/utils/fd_ssload.c:68-143`

## Summary

When loading a snapshot, manifest fields (capitalization, lamports_per_signature, epoch_schedule parameters, inflation rates, rent parameters) are copied directly to bank state without semantic validation. A crafted snapshot can inject arbitrary values for these fields, potentially causing economic state corruption, division-by-zero, or consensus divergence.

## Technical Details

```c
// fd_ssload.c (representative lines)
fd_bank_capitalization_set( bank, manifest->capitalization );
fd_bank_lamports_per_signature_set( bank, manifest->lamports_per_signature );
// epoch_schedule, inflation, rent params all copied directly
```

No validation that:
- `capitalization` is within a sane range (could be ULONG_MAX)
- `slots_per_epoch` is non-zero (used as divisor elsewhere)
- `lamports_per_signature` is reasonable
- Inflation/rent floats are in valid ranges (not NaN, not negative)

The parser (`fd_ssmanifest_parser.c`) only validates one field: `warmup` must be ≤1 (a boolean). All other numeric fields are accepted as-is from the snapshot binary.

## Impact

- `slots_per_epoch = 0` → division by zero in epoch calculations
- `capitalization = ULONG_MAX` → arithmetic overflow in fee calculations
- Extreme `lamports_per_signature` → fee manipulation
- NaN/negative inflation → unpredictable economic behavior
- Consensus divergence if validator starts from corrupted state

**Mitigating factors**: Snapshots are typically downloaded from trusted sources (RPC providers, community snapshots). An attacker would need to compromise the snapshot source or MITM the download. Validators usually verify snapshots against known bank hashes.

## Remediation

Add range validation for all manifest fields before applying to bank state:
```c
FD_TEST( manifest->epoch_schedule.slots_per_epoch > 0 );
FD_TEST( manifest->capitalization <= MAX_EXPECTED_CAPITALIZATION );
FD_TEST( isfinite(manifest->inflation.initial) && manifest->inflation.initial >= 0.0 );
// etc.
```

## References

- `src/discof/restore/utils/fd_ssload.c:68-143` (manifest application)
- `src/discof/restore/utils/fd_ssmanifest_parser.c` (manifest parsing)
