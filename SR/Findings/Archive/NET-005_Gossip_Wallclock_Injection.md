# MEDIUM: Gossip CRDS Wallclock Timestamp Injection

**Category**: NET
**Severity**: Medium
**Component**: Gossip Protocol (CRDS)
**Location**: `src/flamenco/gossip/crds/fd_crds.c:808-837`

## Summary

The CRDS override logic (`overrides_fast()`) determines which value is canonical purely by comparing `wallclock_nanos` timestamps — the larger timestamp wins. While the parser enforces an absolute upper bound (`WALLCLOCK_MAX_MILLIS`), there is no validation that the timestamp is within a reasonable delta of the node's local clock. An attacker can inject CRDS values with far-future timestamps that override all legitimate entries for the same key.

## Technical Details

The parser applies a basic absolute bound:
```c
// fd_gossip_msg_parse.c
#define CHECKED_WALLCLOCK_LOAD( var_name ) \
  ulong _wallclock_ms = FD_LOAD( ulong, CURSOR ); \
  CHECK( _wallclock_ms < WALLCLOCK_MAX_MILLIS ); \
  (var_name) = FD_MILLI_TO_NANOSEC( _wallclock_ms );
```

But the CRDS override logic is purely comparative:
```c
// fd_crds.c:808-837 (overrides_fast)
if( FD_UNLIKELY( candidate_wc > existing_wc ) ) return 1;  // newer wins
else if( FD_UNLIKELY( candidate_wc < existing_wc ) ) return 0;
return -1;  // tie
```

No check like `abs(candidate_wc - local_now) < MAX_DRIFT` exists. An attacker can set `wallclock_nanos` to the maximum allowed value (years in the future), causing their CRDS entry to override the legitimate entry and persist until the local clock catches up.

## Impact

- Attacker-injected CRDS values (contact info, vote state) become canonical across the network
- Legitimate updates cannot override the attacker's entry (their future timestamp always wins)
- Enables eclipse attacks: inject false contact info pointing validators to attacker-controlled IPs
- Entries persist for a very long time (until wallclock catches up or entry is evicted)

**Mitigating factors**: Gossip messages require valid Ed25519 signatures, so the attacker can only inject values signed by their own key (they cannot forge another validator's contact info). Attack is primarily useful for injecting the attacker's own CRDS entries with sticky high timestamps.

## Remediation

Add a local-time delta check before accepting CRDS values:
```c
long drift = candidate_wc - local_now;
if( drift > MAX_CLOCK_DRIFT_NS || drift < -MAX_CLOCK_DRIFT_NS ) {
  return 0; // reject
}
```

## References

- `src/flamenco/gossip/crds/fd_crds.c:808-837` (override logic)
- `src/flamenco/gossip/fd_gossip_msg_parse.c:57-60` (wallclock parsing)
