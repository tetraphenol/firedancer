# CONSENSUS-004: FEC Resolver Silently Drops Conflicting Shreds (Equivocation Non-Detection)

**Category**: Consensus
**Severity**: HIGH
**Component**: FEC Resolver (`fd_fec_resolver.c`)
**Status**: Confirmed

## Summary

When a duplicate shred arrives at the same FEC index, the FEC resolver checks only set membership (`d_rcvd_test`) — not content equality. Two shreds with the same index but different payloads (equivocation) result in the second shred being silently dropped with `FD_FEC_RESOLVER_SHRED_IGNORED`. No equivocation alarm is raised, allowing a malicious leader to send conflicting blocks to different validators without detection at the FEC layer.

## Technical Details

### Duplicate Detection (lines 508-514)
```c
int shred_dup = fd_int_if( is_data_shred,
                           d_rcvd_test( ctx->set->data_shred_rcvd,   in_type_idx ),
                           p_rcvd_test( ctx->set->parity_shred_rcvd, in_type_idx ) );

if( FD_UNLIKELY( shred_dup ) ) return FD_FEC_RESOLVER_SHRED_IGNORED;
```

`d_rcvd_test` / `p_rcvd_test` are simple bitset membership tests. They return 1 if the index has been seen before, regardless of content. No `memcmp` or hash comparison is performed.

### Attack Scenario

1. Malicious leader sends `Shred[idx=0, payload=BlockA]` to validators V1..V500
2. Leader sends `Shred[idx=0, payload=BlockB]` to validators V501..V1000
3. When V1 receives `Shred[idx=0, payload=BlockB]` via gossip:
   - `d_rcvd_test(data_shred_rcvd, 0)` returns 1 (already seen)
   - Returns `FD_FEC_RESOLVER_SHRED_IGNORED` — no content comparison
   - No equivocation proof generated
4. V1 and V501 build different blocks for the same slot

### What SHOULD Happen

When a shred at an already-received index arrives with different content, the resolver should:
1. Compare the new shred's content against the stored shred
2. If different, generate an equivocation proof (`fd_eqvoc`)
3. Propagate the proof via gossip for slashing

### Why Merkle Validation Doesn't Help

Individual shreds have Merkle proofs validated at reception (lines 468-481). But the Merkle root comes from the leader's signature — the leader signs BOTH conflicting Merkle roots. Each shred individually passes validation; only cross-comparison reveals equivocation.

## Impact

- **Equivocation evasion**: Malicious leader sends conflicting blocks without triggering duplicate detection
- **Consensus split**: Different validators build different block histories for the same slot
- **Slashing evasion**: No equivocation proof generated → no economic punishment
- **Network partition**: Prolonged disagreement about block content

## Remediation

Compare shred content on duplicate detection:
```c
if( FD_UNLIKELY( shred_dup ) ) {
  /* Compare content of stored shred vs incoming */
  uchar * stored = /* retrieve stored shred at in_type_idx */;
  if( memcmp( stored, shred_payload, shred_sz ) != 0 ) {
    /* EQUIVOCATION DETECTED — generate proof */
    fd_eqvoc_report( ... );
  }
  return FD_FEC_RESOLVER_SHRED_IGNORED;
}
```

## References

- `src/disco/shred/fd_fec_resolver.c:508-514` (duplicate check)
- `src/disco/shred/fd_fec_resolver.c:468-481` (Merkle validation)
- `src/disco/shred/fd_fec_resolver.c:647-652` (completion validation)
