# INVALID: Bundle Transaction Count Out-of-Bounds in Pack Tile

**Category**: IPC
**Severity**: N/A (Invalid)
**Component**: Pack Tile (Dedup→Pack boundary)
**Invalidation Reason**: `fd_pack_insert_bundle_init()` at `fd_pack.c:1389` contains `FD_TEST( txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE )` which is always compiled in (calls `FD_LOG_ERR` → process abort). The OOB write never occurs; the pack tile aborts instead. Since the attack requires a compromised upstream tile and the result is only a crash (not code execution), this is not an escalation — a compromised tile can already DoS the validator trivially.
**Location**: `src/disco/pack/fd_pack_tile.c:916-930`

## Summary

The pack tile receives `bundle_txn_cnt` from dedup's metadata without validating it against the fixed-size `_txn[FD_PACK_MAX_TXN_PER_BUNDLE]` array (5 elements). A large `bundle_txn_cnt` causes out-of-bounds array access when subsequent bundle transactions arrive and `txn_received` increments past the array boundary.

## Technical Details

When a bundle arrives, pack copies the transaction count directly from the Tango message metadata:

```c
// fd_pack_tile.c:916
ctx->current_bundle->txn_cnt = txnm->block_engine.bundle_txn_cnt;
// ...
ctx->current_bundle->bundle = fd_pack_insert_bundle_init(
    ctx->pack, ctx->current_bundle->_txn, ctx->current_bundle->txn_cnt);
```

The `_txn` array is statically sized:
```c
fd_txn_e_t * _txn[ FD_PACK_MAX_TXN_PER_BUNDLE ]; // = 5
```

The only check is `txn_cnt == 0` (line 920). No upper bound validation exists. As transactions for the bundle arrive, `txn_received` increments and indexes into `bundle[]` which aliases `_txn[]`, reading/writing past the 5-element boundary.

## Proof of Concept

Requires a block engine or compromised dedup tile to emit a transaction with `block_engine.bundle_txn_cnt > 5`. Each subsequent bundle transaction increments `txn_received`, indexing past `_txn[4]` into adjacent memory in the pack context struct.

## Impact

- Memory corruption in pack tile context (fields adjacent to `_txn[]`)
- Pack tile crash or state poisoning
- Potential transaction censorship via corrupted pack state

## Remediation

Add bounds check after line 916:
```c
if( FD_UNLIKELY( txnm->block_engine.bundle_txn_cnt > FD_PACK_MAX_TXN_PER_BUNDLE ) ) {
  /* drop or log */
  return;
}
```

## References

- `src/disco/pack/fd_pack_tile.c:916-930` (bundle init)
- `src/disco/pack/fd_pack_tile.c:1107` (txn_received increment)
- `FD_PACK_MAX_TXN_PER_BUNDLE` definition
