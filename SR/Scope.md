# Firedancer v1.0 Audit Contest - Scope

**Program:** https://immunefi.com/audit-competition/firedancer-v1-audit-comp
**Duration:** April 9 - May 9, 2026
**Prize Pool:** $1,000,000 USDC on Solana

---

## In-Scope Asset

| Asset | Branch | LoC |
|-------|--------|-----|
| https://github.com/firedancer-io/firedancer | v1.0 | ~636,000 nSLOC (C/C++) |

Scope is the **`firedancer` binary** and all code reachable from it. The Frankendancer binary (`fdctl`/`fddev`) and code only reachable from it is explicitly excluded.

Key distinction: `src/discof/` is Firedancer-only; `src/discoh/` is Frankendancer-only. Most other code is shared - see topology files for the authoritative split:
- Firedancer: `src/app/firedancer/topology.c`
- Frankendancer: `src/app/fdctl/topology.c`

---

## Impacts in Scope

### Critical

1. **Loss of funds or acceptance of forged/invalid signatures** - e.g. processing a transaction with an invalid signature, accepting a forged block
2. **Key compromise or exfiltration exploit chains** - e.g. attacker recovers validator signing key
3. **Runtime conformance bugs leading to loss of funds** - e.g. divergence from Agave in account state updates that causes slashing or incorrect balances
4. **Infinite mint bugs enabling unauthorized token creation** - e.g. creating tokens or SOL without authorization

### High

5. **Bank hash mismatch or cluster-wide consensus failure** - e.g. Firedancer computes a different bank hash than Agave, causing a fork or network split
6. **Sandbox escape (tile isolation bypass)** - escaping from a sandboxed tile to the host OS or another tile's process; tile-to-tile attacks (compromised tile model) are excluded
7. **Accounts database corruption enabling delayed loss of funds** - e.g. corrupting funk in a way that leads to incorrect account balances
8. **Arbitrary write primitives in execution tiles** - e.g. memory corruption that allows writing to arbitrary locations within an execution tile
9. **Remotely triggerable cluster-wide liveness failure** - a single attacker can halt the entire cluster or a significant fraction of it

### Medium

10. **Invalid block production** - the validator produces a block that is rejected by the network
11. **Leader slot skipping** - the validator fails to produce blocks during its assigned leader slots
12. **Remotely triggerable leader validator crash** - an attacker can crash a single validator that is currently the leader

### Low

13. **Limited liveness issues** - configuration-dependent or time-windowed liveness failures that affect only a subset of validators or require specific conditions

---

## Reward Structure

Rewards unlock based on the highest severity bug found:
- No valid bugs found: $50,000 minimum payout
- High/Critical bugs absent, only Medium/Low found: $250,000
- High severity found: $500,000
- Critical severity found: $1,000,000

Allocation across pools: Primary ($700k), All Stars ($200k), Podium ($100k).

---

## Out of Scope

### Excluded Codebases / Binaries
- Frankendancer binary (`fdctl`, `fddev`) and code paths only reachable from it
- `src/discoh/` (Frankendancer-only tiles)
- `agave/` Rust submodule (Solana Agave client)
- Development/test/CI tooling, scripts, build system

### Excluded Attack Classes
- **Tile-to-tile attacks:** Assuming a tile is already compromised is not a valid attacker model
- **Solana protocol bugs:** Bugs in the Solana protocol spec itself, not Firedancer's implementation
- **Social engineering** against operators
- **Physical access** attacks
- **Feature gates not activated on mainnet** - behavior gated behind inactive feature flags
  - The only features not active on mainnet that *are* in scope are:
    - reenable_zk_elgamal_proof_program
    - alt_bn128_little_endian
    - enable_bls12_381_syscall
    - enable_alt_bn128_g2_syscalls
  - You can check the features that are active on mainnet (at least recent ones) at: `https://explorer.solana.com/feature-gates`

### Excluded by Known Issues

The following GitHub issues list bugs that are acknowledged and ineligible for rewards:

| Issue | Component | Summary |
|-------|-----------|---------|
| [#9154](https://github.com/firedancer-io/firedancer/issues/9154) | Bundle client | Error handling, unchecked return values |
| [#9157](https://github.com/firedancer-io/firedancer/issues/9157) | Consensus (tower/ghost/choreo) | Float arithmetic, stale block fields, dead code in bank advance |
| [#9159](https://github.com/firedancer-io/firedancer/issues/9159) | Equivocation detection | Merkle proof verification, stale FEC map entries, hardcoded indices, missing slot validation |
| [#9160](https://github.com/firedancer-io/firedancer/issues/9160) | Gossip | PullRequest Bloom Filter exhaustion, untrusted txn length in verify tile |
| [#9161](https://github.com/firedancer-io/firedancer/issues/9161) | Pack/bank/execle | Malicious trailers from pack tile, untrusted OOB writes, lazy CU accounting DoS |
| [#9162](https://github.com/firedancer-io/firedancer/issues/9162) | Proof of History | Integer underflow from untrusted execle sizes, inverted slot guard |
| [#9164](https://github.com/firedancer-io/firedancer/issues/9164) | Program cache | Stale entry assertions, invalidation logic |
| [#9165](https://github.com/firedancer-io/firedancer/issues/9165) | QUIC/networking | Strict fragment validation, unlimited frame processing, low-bandwidth DoS, unreleased TPU slots |
| [#9166](https://github.com/firedancer-io/firedancer/issues/9166) | Repair/forest/blockstore | FEC chain verification, forest cycles, repair flow assertions, stale orphan queue entries |
| [#9168](https://github.com/firedancer-io/firedancer/issues/9168) | RPC/HTTP2 | H2 RST_STREAM buffer checks, untrusted bank index from replay tile |
| [#9170](https://github.com/firedancer-io/firedancer/issues/9170) | VM/SBPF/ELF loader | CPI error handling divergence, log mismatches, .text ordering, ELF crash on SHT_NOBITS |
| [#9171](https://github.com/firedancer-io/firedancer/issues/9171) | Runtime/execution | Snapshot hash bypass, stake delegation divergence, executor UAF, vote misclassification, UBSAN findings |
| [#9172](https://github.com/firedancer-io/firedancer/issues/9172) | Seccomp/sandboxing | 32-bit argument check bypass on x86_64 |
| [#9173](https://github.com/firedancer-io/firedancer/issues/9173) | Shred processing | Fuzz coverage gap for fd_fec_resolver_add_shred |
| [#9175](https://github.com/firedancer-io/firedancer/issues/9175) | Sign tile | Sign tile exhaustion DoS, two-signature response incorrect size |
| [#9176](https://github.com/firedancer-io/firedancer/issues/9176) | Snapshot/vinyl/restore | Broad set of vinyl/snapshot/ssarchive issues (see issue for full list) |
| [#9177](https://github.com/firedancer-io/firedancer/issues/9177) | Utilities/infra | Float-to-unsigned conversion, FD_LAYOUT alignment, deepasan redzones, MAP_remove gaps |
| [#9178](https://github.com/firedancer-io/firedancer/issues/9178) | Verify/dedup/resolv | Cross-tile buffer overflow from dedup to resolv |

---

## Proof of Concept Requirements

A **runnable PoC is mandatory** for all severity levels. Submissions without a working PoC will not be considered.

Use a localnet for testing - testing on mainnet or public testnets is prohibited.

Setup docs: Firedancer Localnet Setup (Google Doc linked from Immunefi resources tab).

---

## Prior Audit Reports

Located in `SR/PriorAudits/`:

| File | Auditor | Scope | Notes |
|------|---------|-------|-------|
| `Neodyme-Firedancer_v0.1_Audit.txt` | Neodyme AG | v0.1 (7 researchers, Apr-Jun 2024) | No RCE found; 2 high (one remote crash), mostly DoS |
| `Neodyme-Firedancer_v0.4_Audit.txt` | Neodyme AG | v0.4 (Feb-Mar 2025) | No RCE found; 1 high (feature activation edge case), mostly QUIC DoS |
| `Atredis_Partners-Firedancer_v0.1_Audit.txt` | Atredis Partners | v0.1 | Independent review |
| `Cure53-GUI_HTTP_Audit.txt` | Cure53 | GUI/HTTP layer | Narrowly scoped to HTTP/metrics interface |
| `Cure53-firedancer_metrics_audit.txt` | Cure53 | Metrics subsystem | Narrowly scoped |

---

## Context vs Frankendancer Bug Bounty

The previous Frankendancer engagement covered both binaries; this contest is scoped to Firedancer only. Key differences:

- Firedancer uses `src/discof/` tiles exclusively (not `src/discoh/`)
- Firedancer does not use the `agave/` Rust submodule at runtime
- The runtime execution engine (`src/flamenco/`) is fully in C for Firedancer
- See `SR/Frankendancer_vs_Firedancer.md` for detailed analysis of the split

Many prior findings in `SR/Findings/` predate this contest and were written against the Frankendancer scope. Validate each against Firedancer's code paths before including in a submission.
