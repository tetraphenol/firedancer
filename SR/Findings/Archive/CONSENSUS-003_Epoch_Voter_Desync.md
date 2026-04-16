# MEDIUM-HIGH: Epoch Voter List Desynchronization in Tower Threshold Check

**Category**: CONSENSUS
**Severity**: Medium-High
**Component**: Tower BFT (Choreo)
**Location**: `src/choreo/tower/fd_tower.c:272-283`

## Summary

The Tower BFT threshold check silently skips voters whose public keys are missing from the cached `epoch_voters` set. At epoch boundaries, the cache can be stale, causing legitimate validator stakes to be excluded from threshold calculations. The code has an explicit TODO acknowledging this is unresolved.

## Technical Details

```c
// fd_tower.c:272-283
fd_voter_t * voter = fd_epoch_voters_query( epoch_voters, vote_keys[i], NULL );
if( FD_UNLIKELY( !voter ) ) {
  /* This means that the cached list of epoch voters is not in sync with the list passed
     through from replay. This likely means that we have crossed an epoch boundary and the
     epoch_voter list has not been updated.

     TODO: update the set of account in epoch_voter's to match the list received from replay,
         so that epoch_voters is correct across epoch boundaries. */
  FD_LOG_CRIT(( "[%s] voter %s was not in epoch voters", __func__,
    FD_BASE58_ENC_32_ALLOCA(&vote_keys[i]) ));
  continue;  // <-- skips this voter's stake
}
threshold_stake += voter->stake;
```

When a voter is not found, `continue` skips adding their stake to `threshold_stake`. This makes the threshold percentage artificially lower, potentially causing valid votes to be rejected or invalid fork choices to be accepted.

## Proof of Concept

Trigger condition: epoch boundary transition while `fd_tower_threshold_check()` is executing, before `epoch_voters` cache is updated to reflect the new epoch's voter set.

## Impact

- Incorrect fork choice threshold calculations at epoch boundaries
- Valid votes potentially rejected (false negative on threshold check)
- Consensus stall or incorrect fork selection during epoch transitions
- The `FD_LOG_CRIT` fires but execution continues via `continue`

## Remediation

Implement the TODO: synchronize `epoch_voters` with the replay-provided vote_keys before performing threshold checks. Alternatively, fail closed (reject the threshold check entirely) rather than silently skipping unknown voters.

## References

- `src/choreo/tower/fd_tower.c:270-284` (threshold check function)
- The TODO comment at lines 274-279 explicitly acknowledges this issue
