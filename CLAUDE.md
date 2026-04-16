- The top-level objective is to conduct a thorough, expert-level, security assessment of the codebase
- Before you begin any task, make sure you've read `SR/Doc.md` if it exists, and `SR/Scope.md`
- Be concise in all of your output, unless specifically responding to a direct user query
- If at any point you discover a vulnerability, document it in a new file: `./SR/Findings/Writeups/<CATEGORY>-NNN_Description.md`
  - Write-ups should be concise (unless otherwise specified):
    - Include all important details to allow an expert to quickly locate and understand the vulnerability
    - Don't include code snippets
    - Don't explain generic concepts
    - Don't include unnecessary context or background
- If you are asked to 'proceed' or 'continue' at the beginning of a fresh conversation (with no additional context given), use your `/cr` skill.
- Don't spin up more than 5 concurrent subagents at a time
- Don't use ALL CAPS for emphasis
- Don't use emdashes (use a hyphen instead: -)

## Assessment Context

**Program:** Firedancer v1.0 - Immunefi Audit Contest
**Duration:** April 9 - May 9, 2026
**Prize Pool:** $1,000,000 USDC
**Target:** `firedancer` binary and all reachable code on the v1.0 branch
**Repo:** `/home/user/FiredancerAC/firedancer` (branch: v1.0)
**Detailed scope:** See `SR/Scope.md`

## Key Constraints

- **Attacker model:** Remote-only; no pre-existing validator access assumed
- **PoC required:** Runnable proof-of-concept mandatory for all severity levels
- **Frankendancer is out of scope** - code only reachable via `fdctl`/`fddev` is excluded
- Tile-to-tile attacks (assuming a compromised tile) are out of scope
- Feature gates not activated on mainnet are out of scope
- Known issues listed in GitHub issues #9154, #9157, #9159-9162, #9164-9166, #9168, #9170-9173, #9175-9178 are excluded

## Repository Layout (relevant paths)

- `src/app/firedancer/` - Firedancer-specific app entry points and topology
- `src/discof/` - Firedancer-only tiles
- `src/disco/` - Shared tile infrastructure (verify, dedup, pack, etc.)
- `src/waltz/` - Network layer (QUIC, TLS, XDP/AF_XDP, gossip)
- `src/ballet/` - Cryptography (ED25519, SHA, AES-GCM, etc.)
- `src/flamenco/` - Runtime, VM (sBPF), ELF loader, features, types
- `src/choreo/` - Consensus (tower BFT, ghost, equivocation detection)
- `src/funk/` - Accounts database (funk key-value store)
- `src/groove/` - Account state layer
- `src/vinyl/` - Snapshot system
- `src/tango/` - IPC messaging (mcache, dcache, tcache, cnc)
- `src/util/` - Utilities, memory management, sandboxing

## Prior Research

The `SR/` directory contains extensive research from the Frankendancer bug bounty engagement. Much of the codebase overlaps, but scope differs - consult `SR/Scope.md` for what's in vs out.

Prior audit reports (converted to text) are in `SR/PriorAudits/`.
