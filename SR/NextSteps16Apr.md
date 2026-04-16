  Where to take this next

  What we know

  Done and clean:
  - Execution-layer differential fuzzing across every sol_compat_* target (~2B+ execs, 0 exploitable findings)
  - Manual triage of all mismatch classes

  Confirmed findings:
  - STAKES-001 (HIGH) - commission cascade divergence at epoch boundary
  - CONS-001 (MEDIUM) - vote poisoning via missing authorized voter check

  Known issues (excluded from scope): 18 GitHub issues covering QUIC DoS, gossip Bloom filter exhaustion, seccomp bypass, shred/FEC issues, verify/dedup OOB write, reward hash bypass, executor UAF, vinyl
  snapshot issues, and more. This is a very broad self-disclosure that narrows the attack surface significantly.

  ---
  What the fuzzing campaign proved (and didn't prove)

  The campaign proved instruction/syscall/transaction execution conformance on common paths - a necessary but not sufficient condition for correctness. It did NOT cover:

  - Epoch boundary execution (stake activation/deactivation, reward distribution, commission selection)
  - Long-running state across many epochs (our harness executes single transactions in isolation)
  - Funk accounts database integrity
  - The full network ingress path for crashes and memory corruption
  - Consensus/tower correctness on adversarial vote sequences

  ---
  Priority ranking for remaining time

  1. Epoch boundary and reward computation (HIGH ceiling, demonstrated productive)

  STAKES-001 came from here. The area is: src/flamenco/stakes/, src/flamenco/rewards/, src/flamenco/epoch/. The code manages stake history across three epoch boundaries simultaneously (t_1, t_2, t_3) and the
  FD representation differs structurally from Agave's. Any divergence in reward amounts = different lamport balances = bank hash mismatch (HIGH). Specific angles:

  - Whether any other stake queries (beyond query_t_1/t_2) silently conflate zero-stake and absent
  - How fd_epoch_stakes is initialized from snapshots vs. computed from scratch
  - The inflation and vote credits calculation against Agave's calculate_rewards_and_distribute_vote_rewards
  - Edge cases in stake delegation transitions across epoch boundaries (partial activations, multiple re-delegations)

  2. Funk accounts database (HIGH ceiling, relatively untouched)

  src/funk/ is a custom memory-mapped KV store with its own transaction semantics, reference counting, and allocator. It's the authoritative source for all account state. Known issues (#9177) touched only
  utility-layer MAP gaps, not funk internals. This is a meaningful gap. The attack surface:

  - fd_funk_txn.c - transaction publish/cancel/squash, particularly concurrent access patterns and the parent-child tree
  - fd_funk_rec.c - record lookup, remove, and the tombstone/resurrection logic
  - fd_funk_val.c - value storage and reallocation, especially alignment and size handling
  - The interaction between funk transactions and execution tiles - if the execution tile gets a reference to a funk record and the record is reallocated underneath it, that's a UAF/arbitrary-write candidate
  (scope #8 explicitly calls this out)

  3. QUIC/TLS - beyond #9165 (MEDIUM/HIGH, high throughput of untrusted input)

  Known issue #9165 covers: strict fragment validation, unlimited frame processing, low-bandwidth DoS, unreleased TPU slots. What it doesn't cover:

  - TLS 1.3 handshake state machine (src/waltz/tls/) - certificate parsing, ClientHello extensions, key derivation. Incorrect bounds checks here could be memory corruption.
  - QUIC connection migration / path validation - receiving a PATH_CHALLENGE on an attacker-controlled address and responding incorrectly
  - CRYPTO frame reassembly (src/waltz/quic/fd_quic_crypto.c) across handshake epochs - mishandling of overlapping or out-of-order CRYPTO data
  - These could reach crash (MEDIUM) or worse if the bug is in a pre-sandbox path

  4. Verify tile - signature verification (Critical ceiling)

  The verify tile is the gateway for all incoming transactions. A bug that allows invalid signatures to pass verification would be Critical (#1 in scope). The known issues cover an OOB write in dedup (#9178)
  and untrusted txn length (#9160) but not the signature verification logic itself. The verify tile (src/disco/verify/) calls into src/ballet/ed25519/ for signature verification - the C implementation of
  Ed25519 batch verification. This is worth a careful read for:

  - Scalar clamping/reduction edge cases
  - Batch verification failures (malformed input causing the whole batch to pass)
  - How rejected transactions are handled vs. accepted ones - is there a state mismatch path

  5. Gossip CRDS processing (MEDIUM/HIGH)

  Beyond the Bloom filter DoS (#9160), the gossip tile processes arbitrary CRDS records from any peer. The record types include ContactInfo, LegacyContactInfo, Vote, LowestSlot, EpochSlots, and others. Any of
  these could trigger memory corruption or incorrect state updates. The attacker model is ideal - gossip port is openly reachable, no authentication required to send records.

  ---
  Recommended sequence

  Given 3 weeks remaining and a reward cliff at HIGH ($500K vs $250K), the priority is finding a second confirmed HIGH before doing anything else.

  This week: Epoch boundary - src/flamenco/stakes/fd_stakes.c, src/flamenco/rewards/fd_rewards.c. Read Agave's equivalent (bank/src/bank.rs calculate_reward_points, distribute_inflation_rewards) in parallel
  and diff the logic structurally. Look specifically for any other places where FD uses stake > 0 as a proxy for "account exists."

  Next week: Funk - src/funk/fd_funk_txn.c and fd_funk_rec.c. Then QUIC/TLS.

  Final week: Verify tile, gossip CRDS, and anything that turned up leads from the earlier work.

  The fuzzing campaign is a sunk cost at this point - it gave us high confidence in execution conformance and cleared the obvious differential bugs. The remaining value is in manual review of complex stateful
  logic (epoch boundaries, accounts database) and the network ingress path (QUIC/TLS, gossip, verify).