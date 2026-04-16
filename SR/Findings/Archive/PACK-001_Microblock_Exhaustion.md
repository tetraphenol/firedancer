# MEDIUM: Microblock Budget Exhaustion via Minimal-CU Bundles

**Category**: PACK
**Severity**: Medium
**Component**: Pack Tile (Block Scheduling)
**Location**: `src/disco/pack/fd_pack.c:2271-2277`

## Summary

Each transaction in a bundle becomes a separate microblock (confirmed by code comment at line 2271). An attacker who controls bundle submission can exhaust the `max_microblocks_per_block` budget with minimal-compute-unit transactions, consuming 100% of microblock slots while using <3% of the CU budget. This prevents any further transactions from being scheduled in the block.

## Technical Details

```c
// fd_pack.c:2271-2277
/* Each transaction in a bundle turns into a microblock */
if( FD_UNLIKELY( microblock_limit==0UL ) ) {
  doesnt_fit = 1;
  FD_MCNT_INC( PACK, MICROBLOCK_PER_BLOCK_LIMIT, 1UL );
  break;
}
microblock_limit--;
```

Each bundle transaction decrements `microblock_limit` independently. A bundle with N transactions consumes N microblock slots. With `max_microblocks_per_block` typically ~128-1000, a single large bundle (or several bundles) of minimal-CU transactions can exhaust all slots.

Example: 500 transactions at minimum CU (~1020 each) = 510K CU total (~1% of 48M CU budget), but 500 microblock slots consumed.

## Impact

- Block utilization waste: <3% CU capacity used, 100% microblock capacity consumed
- All subsequent transactions (including high-fee, high-value) cannot be scheduled
- Effective censorship during the attacker's leader slots
- Attack cost is low (minimal CU transactions with enough priority fee to beat eviction)

**Mitigating factors**: Requires ability to submit bundles (block engine access), not just regular transactions. Regular transactions are packed into shared microblocks, so this attack vector is bundle-specific.

## Remediation

Options:
1. Apply a per-microblock CU minimum (e.g., each microblock must contain at least X CU)
2. Limit microblocks per bundle proportional to CU content
3. Pack multiple bundle transactions into a single microblock where write-locks allow

## References

- `src/disco/pack/fd_pack.c:2271-2277` (microblock decrement per bundle tx)
- `src/disco/pack/fd_pack.c:2501-2503` (microblock limit enforcement)
- `src/disco/pack/fd_pack.c:2427` (microblock_cnt increment)
