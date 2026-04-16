# MEDIUM: Ghost Fork Choice Crash via Vote for Unseen Slot

**Category**: CONSENSUS
**Severity**: Medium
**Component**: Ghost Fork Choice / Tower Tile
**Location**: `src/discof/tower/fd_tower_tile.c:130`, `src/choreo/ghost/fd_ghost.c:374`

## Summary

The tower tile crashes with `FD_LOG_CRIT` (process abort) when it encounters a vote referencing a slot that does not exist in the Ghost fork choice tree. A malicious validator can trigger this by voting for blocks on a private fork that the target validator has never received, then getting the vote transaction included on the main fork.

## Technical Details

When a block is replayed, the tower tile processes vote accounts to update Ghost fork weights. At `fd_tower_tile.c:118-131`:

```c
ulong vote = fd_tower_votes_peek_tail( tower )->slot;  // most recent vote in tower
// ...
if( FD_LIKELY( vote != FD_SLOT_NULL && vote >= fd_ghost_root( ctx->ghost )->slot ) ) {
    fd_ghost_ele_t const * ele = fd_ghost_query_const( ctx->ghost, fd_ghost_hash( ctx->ghost, vote ) );

    /* It is an invariant violation if the vote slot is not in ghost.
       These votes come from replay ie. on-chain towers stored in vote
       accounts which implies every vote slot must have been processed
       by the vote program (ie. replayed) and therefore in ghost. */

    if( FD_UNLIKELY( !ele ) ) FD_LOG_CRIT(( "voter %s's vote slot %lu was not in ghost", ... ));
    fd_ghost_replay_vote( ctx->ghost, voter, &ele->key );
}
```

The code path:
1. `fd_ghost_hash(ghost, vote)` returns `NULL` if slot not in Ghost's slot_map
2. `fd_ghost_query_const(ghost, NULL)` returns `NULL` (NULL hash check at `fd_ghost.h:345`)
3. `!ele` → `FD_LOG_CRIT` → `fd_log_private_2()` → `abort()` (process termination)

Additionally, `fd_ghost_replay_vote()` itself has a latent NULL dereference at line 374:
```c
fd_ghost_ele_t const * vote_ele = fd_ghost_query_const( ghost, hash );
ulong slot = vote_ele->slot;  // NULL deref if hash not in Ghost
```
The production caller's `FD_LOG_CRIT` guard at line 130 prevents reaching this code, but the function lacks internal NULL safety.

## Attack Scenario

1. Malicious validator V produces a block for slot X on a private fork (does not broadcast the block)
2. V submits a vote transaction voting for slot X
3. The vote transaction is gossiped and included by a leader on the main fork in block Y
4. Target validator T replays block Y, discovers V's vote account references slot X
5. Slot X is not in T's Ghost (never received the private block)
6. `FD_LOG_CRIT` → T's validator process aborts

**Prerequisites:**
- Attacker must be a validator with stake and valid vote keypair
- Attacker's vote transaction must pass vote program validation
- Target must not have received the private fork's blocks

## Impact

- Validator crash (DoS) requiring restart
- Affects all validators that replay the block containing the malicious vote
- Network-wide impact if many validators are affected simultaneously
- Clean crash with error message (not silent corruption)

**Mitigating factors:**
- Requires malicious validator with active stake
- Solana vote program may validate vote slot/hash consistency (needs verification against Agave)
- Crash is recoverable via restart
- The developer comments acknowledge this as an "invariant violation" (lines 125-128), suggesting the assumption may be intentionally fragile during development

## Remediation

Replace `FD_LOG_CRIT` with graceful skip:
```c
if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_WARNING(( "voter %s's vote slot %lu was not in ghost, skipping",
                     FD_BASE58_ENC_32_ALLOCA( pubkey ), vote ));
    continue;
}
```

Also add NULL safety inside `fd_ghost_replay_vote()`:
```c
fd_ghost_ele_t const * vote_ele = fd_ghost_query_const( ghost, hash );
if( FD_UNLIKELY( !vote_ele ) ) return;
ulong slot = vote_ele->slot;
```

## References

- `src/discof/tower/fd_tower_tile.c:118-131` (production caller with FD_LOG_CRIT guard)
- `src/choreo/ghost/fd_ghost.c:369-446` (fd_ghost_replay_vote with latent NULL deref)
- `src/choreo/ghost/fd_ghost.h:353-359` (fd_ghost_hash slot→hash lookup)
- `src/util/log/fd_log.c:922-949` (fd_log_private_2 always terminates: exit(1) or abort())
- Archive: CONSENSUS-003_Epoch_Voter_Desync.md (similar FD_LOG_CRIT crash pattern at epoch boundary)
