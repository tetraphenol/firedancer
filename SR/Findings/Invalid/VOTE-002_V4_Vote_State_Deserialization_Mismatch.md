# VOTE-002: Vote State Deserializer Enforces Bounds Checks Not Present in Agave

**Severity:** Invalid (not exploitable - bounds match vote program invariants)
**Component:** `src/flamenco/runtime/program/vote/fd_vote_codec.c:193,231,271`

## Description

Firedancer's hand-written vote state deserializer enforces three bounds checks
during deserialization that Agave's custom deserializer does not. Any of these
can independently cause Firedancer to reject a vote state that Agave accepts.

### Cause A: `votes_len > MAX_LOCKOUT_HISTORY (31)` - line 193

The votes deque length is checked against 31. Agave's deserializer uses `.min()`
only for initial Vec allocation capacity but reads ALL entries. Most prolific
cause: 324 of 349 saved mismatch inputs.

### Cause B: `authorized_voters_len > MAX_AUTHORIZED_VOTERS (4)` - line 231

The BTreeMap length is checked against 4. Agave imposes no deserialization limit.
Triggered in 25 saved inputs.

### Cause C: `epoch_credits_len > MAX_EPOCH_CREDITS_HISTORY (64)` - line 271

The epoch credits vector length is checked against 64. Agave has no
deserialization limit. Triggered in 1 saved input (V1 with epoch_credits_len=24576).

### Affected Versions

All three vote state versions are affected:

| Version | votes_len cause | auth_voters cause | epoch_credits cause |
|---------|----------------|-------------------|---------------------|
| V1.14.11 (disc=1) | 16 inputs | 17 inputs | 1 input |
| V3 (disc=2) | 31 inputs | 4 inputs | 0 |
| V4 (disc=3) | 276 inputs | 4 inputs | 0 |

## Why Invalid

All three bounds are invariants maintained by the vote program during execution.
No legitimate program execution path can produce serialized vote account data
exceeding these bounds:

**votes (<=31):** `process_new_vote_state()` (`fd_vote_program.c:499`) rejects
`> MAX_LOCKOUT_HISTORY` before serialization. `fd_vsv_process_next_vote_slot`
uses pop-before-push at capacity. Both Firedancer and Agave enforce this.

**epoch_credits (<=64):** `fd_vsv_increment_credits` pops before push when
`cnt >= 64` (`fd_vote_state_versioned.c:439`). Agave does push-then-pop
(temporarily 65 in memory), but serialized output is always <=64.

**authorized_voters (<=4):** `target_epoch` in `Authorize(Voter)` is hardcoded
to `leader_schedule_epoch + 1` (`fd_vote_program.c:800`), not user-controlled.
On mainnet `leader_schedule_epoch = current_epoch + 1` (constant per epoch,
since `leader_schedule_slot_offset = slots_per_epoch`), so `target_epoch =
current_epoch + 2`. `TooSoonToReauthorize` prevents multiple calls per epoch.
V4 purge keeps entries with `epoch >= current_epoch - 1`, giving a window of
[current_epoch-1, current_epoch+2] = 4 entries max. Traced worst-case
accumulation across epoch boundaries: steady state is exactly 4 (tight but
correct). The claim that "rapid authorized voter changes near epoch boundaries
could produce >4" is incorrect because target_epoch is system-derived and
constant within each epoch.

**No remote vector can trigger the divergence.** All vote account data is
written exclusively through the vote program execution pipeline:
- Transactions (any source): execute through vote program BPF, bounds enforced
- Gossip votes: converted to transactions first
- Leader blocks / turbine shreds / repair: contain transactions, all go through
  standard execution
- Tower tile / rewards / RPC: read-only or balance-only for vote accounts

The divergence can only be triggered by account data not produced by the vote
program (e.g. snapshot corruption or a separate arbitrary-write vulnerability).

## Minimal Reproducers

Crash inputs saved in `SR/Findings/Crashes/`:
- `vote_v4_auth_voters_422.bin` (V4, auth_voters_len=5)
- `vote_v4_votes_602.bin` (V4, votes_len=32)
- `vote_v3_auth_voters_1884.bin` (V3, auth_voters_len=5)
- `vote_v3_votes_2111.bin` (V3, votes_len=32)
- `vote_v1_auth_voters_1908.bin` (V1, auth_voters_len=5)
- `vote_v1_votes_2166.bin` (V1, votes_len=40)
- `vote_v1_epoch_credits_4096.bin` (V1, epoch_credits_len=24576)

Run: `build/native/clang/fuzz-test/fuzz_vote_codec_diff SR/Findings/Crashes/vote_v4_auth_voters_422.bin`

## Found By

Differential fuzzing: `fuzz_vote_codec_diff`. 121M executions, 894 coverage
edges, 349 saved inputs decomposing to 3 root causes across 3 versions.
