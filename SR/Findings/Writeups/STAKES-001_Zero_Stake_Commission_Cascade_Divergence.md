# STAKES-001: Zero-Stake Vote Account Causes Commission Cascade Divergence

## Severity
HIGH (Consensus failure - bank hash divergence between Firedancer and Agave)

## Summary
Firedancer's `fd_vote_stakes_query_t_1()` and `fd_vote_stakes_query_t_2()` conflate "vote account does not exist" with "vote account has zero delegated stake", returning false in both cases. Agave's `VoteAccounts::get()` returns the vote account regardless of stake. When the `delay_commission_updates` feature selects which historical commission to use, this causes Firedancer to skip the correct epoch's commission and fall through to a more recent one, producing different reward distributions and a bank hash divergence.

## Vulnerability Details

**Location:** `src/flamenco/stakes/fd_vote_stakes.c:467-490`

**Root Cause:**

`fd_vote_stakes_query_t_1` (line 476) and `fd_vote_stakes_query_t_2` (line 489) both return `found && *stake_out > 0UL`. This is documented behavior (fd_vote_stakes.h:230-232): "the vote account either did not exist at the end of the t-{1,2} epoch boundary or had zero stake: they are treated as the same thing."

In Agave, `VoteAccounts::get()` (vote_account.rs:233-236) returns the vote account if it exists in the map, regardless of stake. `sub_stake()` (vote_account.rs:318-327) reduces stake to 0 but does not remove the entry. Zero-stake entries persist through `refresh_vote_accounts` (confirmed by the comment at fd_stakes.c:437-440) and into EpochStakes snapshots.

The commission selection at fd_stakes.c:584 uses `exists_t_3` / `exists_t_2` as guards:
```
vote_ele->commission = exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1);
```

When `exists_t_3` is false due to zero stake (not absence), Firedancer falls through to `commission_t_2` or `commission_t_1`. Agave finds the account and uses `commission_t_3`.

The same pattern appears in `fd_rewards.c:995` (`stake_t_2>0UL ? commission_t_2 : commission_t_1`) for the snapshot recovery path.

**Attack Scenario:**

Attacker controls vote account V (vote authority) and can delegate/undelegate freely.

1. Epoch E: V has a small delegation, commission = 5%.
2. Attacker deactivates all delegations to V during epoch E. Cooldown completes by E+2 boundary (small delegations fully deactivate in one epoch).
3. Epoch E+2 boundary: V is seeded into stake_accum_map from parent vote_stakes with stake=0 (fd_stakes.c:452-453). V exists as a valid vote account so `exists_t_1=1` at line 569, and gets inserted into vote_stakes with `stake_t_1=0`.
4. During E+2: attacker changes commission to 100%, creates new delegations.
5. Epoch E+3 boundary: new delegations activate. V inserted with `stake_t_1>0`, `stake_t_2=0` (from E+2 where stake was 0).
6. Epoch E+4 boundary (rewards for E+3):
   - `exists_t_3 = fd_vote_stakes_query_t_2(parent)` reads E+2 data: stake=0, returns false
   - `exists_t_2 = fd_vote_stakes_query_t_1(parent)` reads E+3 data: stake>0, returns true
   - Firedancer selects `commission_t_2` = 100% (from E+3)
   - Agave finds V in snapshot_epoch_vote_accounts (E+2) despite 0 stake, selects 5%

This produces different reward amounts for every stake account delegated to V, causing a bank hash divergence.

**Requirements:**
- A vote account under attacker control (trivial to create)
- Ability to delegate and undelegate SOL (standard operations)
- Ability to change vote account commission (standard VoteUpdate instruction)
- ~4 epochs of setup (~8 days on mainnet)
- No leader slot or significant stake required

## Impact
Consensus failure. Different commission values produce different reward distributions, leading to different account lamport balances and bank hash divergence at the epoch boundary. Firedancer validators would fork from the Agave majority.

## Files
- `src/flamenco/stakes/fd_vote_stakes.c:467-490` (query_t_1/query_t_2 zero-stake filtering)
- `src/flamenco/stakes/fd_stakes.c:557-584` (commission cascade using exists_t_3/exists_t_2)
- `src/flamenco/rewards/fd_rewards.c:994-995` (snapshot recovery path, same pattern)
