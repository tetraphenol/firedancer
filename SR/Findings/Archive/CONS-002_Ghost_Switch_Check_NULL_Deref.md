# CONS-002: Potential NULL Dereference in is_purged During switch_check BFS

## Severity
MEDIUM (Requires further analysis of ghost/tower block invariant)

## Summary
The `is_purged` helper function in `fd_tower.c` dereferences the result of `fd_tower_blocks_query` without a NULL check. If any ghost block in the BFS traversal of `switch_check` lacks a corresponding tower block entry, this causes a NULL pointer dereference crash.

## Vulnerability Details

**Location:** `src/choreo/tower/fd_tower.c:459-460`

**Root Cause:**
```c
static int
is_purged( fd_tower_t * tower, fd_ghost_blk_t * blk ) {
  fd_tower_blk_t * tower_blk = fd_tower_blocks_query( tower, blk->slot );
  return tower_blk->confirmed && memcmp( ... );  // tower_blk may be NULL
}
```

`is_purged` is called from `switch_check` (line 496) during BFS over the ghost tree. It calls `fd_tower_blocks_query` and immediately dereferences without checking for NULL.

**Calling context:**
`switch_check` (line 463-579) iterates over ALL ghost tree children via BFS starting from the ghost root. For each child, it calls `is_purged`. The function is reached from `fd_tower_fork_choice` (line 784) when the validator needs to evaluate a fork switch.

**Current safety analysis:**
Under normal operation, ghost blocks and tower blocks are inserted together in `replay_slot_completed` (tower_tile.c:1006 and 1040). The invariant that all ghost blocks have corresponding tower blocks appears to be maintained. However, there is no defensive NULL check, and if any race condition, pruning mismatch, or edge case breaks this invariant, the process crashes.

**Trigger conditions (hypothetical):**
- A ghost block inserted for a slot where the tower block was pruned but the ghost block was not
- An edge case in root advancement where ghost and tower pruning are not perfectly synchronized
- A ghost block remaining in the tree after an equivocation event removes the tower block

## Impact
If triggerable by a remote attacker (e.g., through carefully timed equivocation proofs), this would crash the validator process during fork choice evaluation. The crash occurs in `switch_check`, which is called whenever the validator evaluates whether to switch forks - a critical consensus path.

## Notes
- The missing NULL check is a defensive coding issue regardless of current reachability
- All other callers of `fd_tower_blocks_query` in the same file check for NULL (e.g., line 672, 838, 873)
- This function is unique in not guarding against NULL
