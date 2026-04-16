# HIGH: Network-Wide Firedancer DoS via Vote Account Epoch Stake Pollution

**Category**: CONSENSUS
**Severity**: High
**Component**: Replay Tile / Tower Tile Pipeline
**Location**: `src/discof/replay/fd_replay_tile.c:619`, `src/discof/tower/fd_tower_tile.c:363`

## Bug Description

The replay tile sends all staked vote accounts from the previous epoch to the tower tile at the end of every slot. The pipeline has a hardcoded capacity of 4,095 accounts (`FD_REPLAY_TOWER_VOTE_ACC_MAX - 1` due to an off-by-one in the bounds check), while the runtime's `vote_states` map supports up to 40,200 (`FD_RUNTIME_MAX_VOTE_ACCOUNTS`).

When the number of staked vote accounts exceeds 4,095, the replay tile aborts:

```c
// fd_replay_tile.c:611-619 — buffer_vote_towers()
fd_vote_states_t const * vote_states = fd_bank_vote_states_prev_locking_query( bank );
for( ... all staked vote accounts in previous epoch ... ) {
    if( FD_UNLIKELY( vote_state->stake == 0 ) ) continue;
    if( FD_UNLIKELY( ctx->vote_tower_out_len >= (FD_REPLAY_TOWER_VOTE_ACC_MAX-1UL) ) )
        FD_LOG_ERR(( "vote_tower_out_len too large" ));  // kills entire validator
    ...
    ctx->vote_tower_out_len++;
}
```

This iterates `vote_states_prev` — the epoch-level snapshot of all staked vote accounts — not the transactions in the current block. The count is determined entirely by epoch state. Vote accounts need not have ever cast a vote to be counted; the only filter is `stake > 0`.

`FD_LOG_ERR` terminates the entire process group (all tiles) via `exit_group(1)`. There is no tile restart mechanism; Firedancer uses a fail-fast cascade model where any tile death kills the whole validator.

This is also a latent scaling cliff: if the network organically grows past 4,095 staked vote accounts (including delinquent validators with dormant stake), Firedancer will crash with no attacker involvement.

## Impact

On restart, the validator replays the same slot and hits the same epoch state, creating a **permanent crash loop** for every Firedancer node (validators and RPC) until the code is patched or the epoch rolls over with fewer vote accounts. Agave validators are unaffected.

The secondary bounds check in the tower tile (`fd_tower_tile.c:363`) is moot since the replay tile crashes first.

## Exploitation

**No special privileges required.** Any SOL holder can execute this. The vote program's `InitializeAccount` instruction only requires that the caller hold the private key for the `node_pubkey` they specify — there is no check that a validator is actually running or has ever voted. The attacker generates all keypairs themselves.

1. **Create ~2,200 vote accounts** (to push the network total from ~1,900 past 4,095). Each requires `InitializeAccount` via the vote program and ~0.027 SOL rent-exempt balance.

2. **Create ~2,200 stake accounts and delegate 1 SOL each** to the corresponding vote accounts. The minimum delegation is 1 SOL on mainnet (`stake_raise_minimum_delegation_to_1_sol` feature is active). Each stake account costs ~0.002 SOL rent.

3. **Wait ~2 epoch boundaries (~4-6 days)**. Stake warms up during epoch E+1, then `vote_states` is copied to `vote_states_prev` at the E+1→E+2 boundary. From the first slot of epoch E+2, every call to `buffer_vote_towers()` exceeds the limit.

4. **Every Firedancer node crash-loops indefinitely.** The epoch state is identical on all nodes and persists across restarts.

**Total capital: ~2,270 SOL (~$300-500).** Nearly all recoverable after deactivating stake and closing accounts. Irrecoverable cost is only transaction fees.

**Stealth considerations:** The ~2 epoch delay between account creation and impact creates a window for detection. To mitigate this, an attacker could create accounts gradually over many epochs (a few dozen per epoch, indistinguishable from new small validators), then push the final batch just before an epoch boundary. Spread across many funding wallets, this would be very difficult to distinguish from organic network growth.

## References

- `src/discof/replay/fd_replay_tile.c:604-629` — `buffer_vote_towers()`, the crashing function
- `src/discof/replay/fd_replay_tile.h:79` — `FD_REPLAY_TOWER_VOTE_ACC_MAX (4096UL)`
- `src/flamenco/runtime/fd_runtime_const.h` — `FD_RUNTIME_MAX_VOTE_ACCOUNTS (40200UL)`
- `src/discof/tower/fd_tower_tile.c:363` — secondary bounds check (unreachable due to replay crash)
- `src/app/shared/commands/run/run.c:410-456` — tile supervision: any tile death kills all tiles
- `src/flamenco/runtime/program/fd_vote_program.c:1791` — `InitializeAccount` only requires node_pubkey signer
- `src/flamenco/stakes/fd_vote_states.c:251-309` — `fd_vote_states_update_from_account()` does not filter by voting activity
