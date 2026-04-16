# Main setup

# Firedancer v1.0 Localnet Setup Guide

This guide walks you through building Firedancer from source and running a local Solana cluster for testing proofs of concept. It is written for the [Firedancer v1.0 Immunefi Audit Contest](https://immunefi.com/) and assumes you are comfortable with Linux and C but may be new to Solana infrastructure.

**What you will have at the end:** A local Solana cluster with one Agave bootstrap validator and one Firedancer validator, both producing blocks and in consensus. You will be able to submit transactions via Agave's RPC, send crafted packets directly to Firedancer, and observe validator behavior — everything needed for a valid PoC submission.

## Table of Contents

1. [System Requirements](#1-system-requirements)  
2. [Install Dependencies](#2-install-dependencies)  
3. [Build Agave (Solana Reference Client)](#3-build-agave-solana-reference-client)  
4. [Build Firedancer](#4-build-firedancer)  
5. [Quick Start: Single-Node Dev Mode](#5-quick-start-single-node-dev-mode)  
6. [Start the Agave Bootstrap Cluster](#6-start-the-agave-bootstrap-cluster)  
7. [Create Firedancer Keys and Stake](#7-create-firedancer-keys-and-stake)  
8. [Configure and Start Firedancer](#8-configure-and-start-firedancer)  
9. [Verify the Cluster](#9-verify-the-cluster)  
10. [Submit a Test Transaction](#10-submit-a-test-transaction)  
11. [Testing PoC Scenarios](#11-testing-poc-scenarios)  
12. [Teardown and Cleanup](#12-teardown-and-cleanup)  
13. [Troubleshooting](#13-troubleshooting)

## 1\. System Requirements

| Component | Minimum |
| :---- | :---- |
| **OS** | Ubuntu 22.04+ (amd64, kernel \>= 4.18) |
| **CPU** | 16 cores recommended (8 minimum) |
| **RAM** | 256 GB recommended (Firedancer v1.0 pre-allocates \~192 GiB hugepages with the localnet tuning below; see [Memory Tuning](http://localnet-memory-tuning.md) for details) |
| **Disk** | 100 GB free (source builds \+ ledger data) |
| **Privileges** | `sudo` access (required for hugepages and sysctl); running firedancer directly as root is unsupported |

**Why so much RAM?** Firedancer v1.0 is designed for mainnet and pre-allocates large memory regions for banks, the blockstore, accounts database, and tile workspaces — all backed by hugepages. The `banks` workspace alone requires \~65 GiB due to hardcoded mainnet-scale constants (241M stake accounts, 19M vote accounts). With the localnet tuning in Section 8c, total hugepage usage is \~192 GiB (98,432 hugepages × 2 MiB). This is a hard floor that cannot be reduced further without code changes. See [Memory Tuning](http://localnet-memory-tuning.md) for a full breakdown. Note that the Agave bootstrap validator also needs a few GB of RAM alongside Firedancer.

**Cloud VMs:** Use instances with at least 256 GB RAM. Set `max_page_size = "huge"` in the Firedancer config (gigantic pages require bare-metal or nested hugepage support).

## 2\. Install Dependencies

### System packages

```shell
sudo apt update && sudo apt install -y \
    git curl build-essential pkg-config \
    libssl-dev libudev-dev zlib1g-dev \
    llvm clang libclang-dev cmake \
    libprotobuf-dev protobuf-compiler \
    python3 python3-pip python3-venv \
    autoconf automake autopoint bison flex \
    gcc-multilib gettext libgmp-dev \
    zstd lcov perl iproute2
```

### Rust (required for Agave and Firedancer dependencies)

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup component add rustfmt
```

### Python packages (optional — for scripted test transactions)

These are only needed if you plan to write Python-based PoC scripts (e.g., the examples in Section 11). The core localnet setup does not require them.

```shell
pip3 install solders solana
```

## 3\. Build Agave (Solana Reference Client)

Agave provides the bootstrap validator and the `solana` CLI tools for managing the cluster.

```shell
cd ~
git clone https://github.com/anza-xyz/agave.git
cd agave
git checkout v3.1.11
git submodule update --init --recursive
./cargo build --release
```

**Agave v3.1.11 compatibility:** Two patches to the `agave-cluster` tool are required before use. These are applied in [Section 4](#4-build-firedancer) after building Firedancer (the file to patch lives in the Firedancer repo).

**Build time:** 20-40 minutes. Uses \~15 GB disk.

Add binaries to PATH:

```shell
export AGAVE_DIR="$HOME/agave"
export PATH="$AGAVE_DIR/target/release:$PATH"
```

Verify:

```shell
agave-validator --version
solana --version
```

## 4\. Build Firedancer

```shell
cd ~
git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git
cd firedancer
git checkout v1.0
git submodule update --init --recursive
```

**Tag:** We build from the [`v1.0` tag](https://github.com/firedancer-io/firedancer/tree/v1.0), which is the release cut for the Immunefi audit contest. The contest scope covers all reachable code in the `firedancer` binary at this tag.

Build dependencies and binaries:

```shell
./deps.sh +dev check fetch install
make -j firedancer-dev
```

The `check fetch install` subcommands run non-interactively (no confirmation prompt). The `+dev` flag is required to build flatcc, a dependency needed for protobuf support. We build `firedancer-dev` because it supports the `dev` subcommand needed for local cluster setup. The in-scope code (tiles, runtime, networking, etc.) is identical between `firedancer` and `firedancer-dev`.

**Build time:** 10-20 minutes for deps, 5-10 minutes for the binary. Requires GCC (the contest scopes GCC 8.5, 13, and 14).

Verify:

```shell
./build/native/gcc/bin/firedancer-dev version
```

Set environment variables:

```shell
export FD_DIR="$HOME/firedancer"
export FD_BIN="$FD_DIR/build/native/gcc/bin/firedancer-dev"
```

### 

### Patch `agave-cluster` for Agave v3.1.11 compatibility

The `agave-cluster` tool (`$FD_DIR/contrib/agave-cluster/agave_cluster/cli.py`) needs two patches before use. Find the `solana-genesis` command (around line 178\) and apply both changes:

1. **Vote State V4 (SIMD-0185) fix:** Agave v3.1.11 introduced Vote State V4, which the BPF stake program bundled with Firedancer cannot deserialize. Change `"--cluster-type", "mainnet-beta"` to `"--cluster-type", "development", "--deactivate-feature", "Gx4XFcrVMt4HUvPzTpTSVkdDVgcDSjKhDN1RqRS6KDuZ"`. Without this fix, stake delegation will fail with "invalid account data for instruction".

2. **Epoch size fix:** The default 256 slots-per-epoch is too small — Firedancer's txsend tile can crash at epoch boundaries when the next epoch's leader schedule is not yet available (`FAIL: leaders[ i ]`). Change `"--slots-per-epoch", "256"` to `"--slots-per-epoch", "2048"`. This gives \~13 minutes between epoch boundaries, long enough for stable operation.

Both patches can be applied with:

```shell
cd $FD_DIR/contrib/agave-cluster/agave_cluster
sed -i 's/"--cluster-type", "mainnet-beta"/"--cluster-type", "development", "--deactivate-feature", "Gx4XFcrVMt4HUvPzTpTSVkdDVgcDSjKhDN1RqRS6KDuZ"/' cli.py
sed -i 's/"--slots-per-epoch", "256"/"--slots-per-epoch", "2048"/' cli.py
```

## 5\. Quick Start: Single-Node Dev Mode

For quick iteration (crafted packets, crash reproduction) that doesn't require consensus testing, Firedancer has a built-in single-node mode. Many bugs can be demonstrated without needing two validators, and this mode is significantly simpler to set up.

```shell
IFACE=$(ip -o -4 addr show scope global | awk '{print $2}' | head -n1)

cat > /tmp/fd-dev.toml << EOF
name = "fd-dev"

[log]
    path = "/tmp/firedancer.log"
    level_stderr = "INFO"

[hugetlbfs]
    max_page_size = "huge"

[layout]
    affinity = "f50"
    net_tile_count = 1
    quic_tile_count = 1
    verify_tile_count = 1
    resolv_tile_count = 1
    gossvf_tile_count = 1
    execle_tile_count = 1
    execrp_tile_count = 1
    shred_tile_count = 1
    sign_tile_count = 2
    snapshot_hash_tile_count = 1
    snapwr_tile_count = 1

[net]
    interface = "$IFACE"

[accounts]
    max_accounts = 1_000_000
    file_size_gib = 1
    max_unrooted_account_size_gib = 1
    cache_size_gib = 1
    write_delay_slots = 8

[runtime]
    max_live_slots = 512
    max_fork_width = 4
    [runtime.program_cache]
        heap_size_mib = 512

[tiles]
    [tiles.gui]
        enabled = false
    [tiles.bundle]
        enabled = false

[development]
    sandbox = false
    no_clone = true

    [development.gossip]
        allow_private_address = true

    [development.genesis]
        validate_genesis_hash = false
EOF

sudo $FD_BIN dev --config /tmp/fd-dev.toml
```

This auto-configures hugepages, generates genesis, creates keys, and starts a single Firedancer validator. RPC will be available on port 8899 (read-only queries like `getSlot`, `getBalance`, `getVersion`).

**When to use the full two-validator setup instead:** Single-node dev mode cannot demonstrate consensus bugs, bank hash mismatches, or cross-validator interactions. For those PoCs, continue to [Section 6](#6-start-the-agave-bootstrap-cluster).

## 6\. Start the Agave Bootstrap Cluster

Firedancer ships with an `agave-cluster` CLI tool that automates genesis creation and Agave bootstrap.

### 6a. Activate the agave-cluster environment

```shell
mkdir -p /tmp/fd-localnet
cd $FD_DIR/contrib/agave-cluster
source activate $FD_DIR $AGAVE_DIR /tmp/fd-localnet
```

### 6b. Raise file descriptor limit

Agave requires a high open-file-descriptor limit. If you see `Unable to increase the maximum open file descriptor limit to 1000000`, run:

```shell
ulimit -n 1000000
```

**Persistent fix:** Add `* soft nofile 1000000` and `* hard nofile 1000000` to `/etc/security/limits.conf` and re-login.

### 6c. Start the cluster

```shell
agave-cluster start-cluster
```

This will:

- Generate a genesis block (with primordial accounts for Firedancer compatibility)  
- Start an Agave bootstrap validator with RPC enabled  
- Fund an authority account for staking operations

Wait for RPC to be ready. Note: `agave-cluster` binds to the server's external IP, not `127.0.0.1`:

```shell
SERVER_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
while ! curl -s http://$SERVER_IP:8899/health 2>/dev/null | grep -q "ok"; do
  echo "Waiting for Agave RPC..."
  sleep 2
done
echo "Agave is ready at http://$SERVER_IP:8899"
```

### 6d. Verify

```shell
agave-cluster status
solana -u http://$SERVER_IP:8899 slot
```

## 7\. Create Firedancer Keys and Stake

Create staked validator keys for Firedancer:

```shell
agave-cluster create-staked-keys --validator-name fd-validator --sol 10
```

This creates a staked validator with 10 SOL. Solana uses progressive stake warmup, so FD's active stake increases each epoch (\~25% per epoch on development clusters). FD will have enough active stake to be assigned leader slots starting in **epoch 2** (not epoch 1). Using only 1 SOL causes FD to get leader slots too late, and using too much (e.g., 100 SOL) can block Agave's supermajority. Key paths:

```
/tmp/fd-localnet/keys/fd-validator/id.json      # Identity keypair
/tmp/fd-localnet/keys/fd-validator/vote.json     # Vote account keypair
```

## 8\. Configure and Start Firedancer

### 8a. Wait for a recent snapshot

Firedancer needs to boot from a snapshot produced *after* its stake was delegated. The snapshot must also be **close to the cluster's current slot** — with `max_live_slots = 512`, FD can only track 512 unrooted slots at a time. If the snapshot is too far behind the cluster head, FD will fill its live slot capacity before establishing a root and stall.

Due to progressive stake warmup, FD's stake is not fully active until epoch 2+, and it will only be assigned leader slots starting in **epoch 2** (slot 4096+), not epoch 1\. FD will join the cluster, catch up, vote through epoch 1, and cross into epoch 2 where it begins producing blocks.

```shell
BOOTSTRAP_DIR="/tmp/fd-localnet/nodes/node-ledger-0"
SERVER_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)

echo "Waiting for a recent snapshot..."
while true; do
  CURRENT=$(solana -u http://$SERVER_IP:8899 slot 2>/dev/null)
  TARGET=$((CURRENT - 200))
  LATEST=$(ls -t $BOOTSTRAP_DIR/snapshot-*.tar.zst 2>/dev/null | head -1)
  if [ -n "$LATEST" ]; then
    SLOT=$(basename "$LATEST" | sed 's/snapshot-\([0-9]*\)-.*/\1/')
    if [ "$SLOT" -ge "$TARGET" ]; then
      echo "Snapshot available at slot $SLOT (cluster at $CURRENT): $LATEST"
      break
    fi
  fi
  echo "Waiting... (latest snapshot at slot ${SLOT:-none}, cluster at ${CURRENT:-?})"
  sleep 10
done
```

**Why a recent snapshot?** FD replays all slots between the snapshot and the cluster head. With `max_live_slots = 512`, if the gap exceeds \~400 slots, FD fills its capacity before the root can advance and deadlocks. Using a snapshot within \~200 slots of the cluster head gives plenty of headroom.

### 8b. Get cluster parameters

```shell
SERVER_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
GENESIS_HASH=$(solana -u http://$SERVER_IP:8899 genesis-hash)
SHRED_VERSION=$(cat /tmp/fd-localnet/cluster-info.txt | grep shred_version | cut -d= -f2)
echo "Genesis: $GENESIS_HASH  Shred: $SHRED_VERSION"
```

### 8c. Create the config file

```shell
FD_KEYS_DIR="/tmp/fd-localnet/keys/fd-validator"
FD_HOME="$HOME/.firedancer/fd-localnet"

cat > /tmp/fd-localnet.toml << EOF
name = "fd-localnet"

[paths]
    identity_key = "$FD_KEYS_DIR/id.json"
    vote_account = "$FD_KEYS_DIR/vote.json"
    base = "$FD_HOME"
    genesis = "$FD_HOME/genesis.bin"
    snapshots = "$FD_HOME/snapshots"

[log]
    path = "/tmp/firedancer.log"
    level_stderr = "INFO"

[hugetlbfs]
    max_page_size = "huge"

[layout]
    affinity = "f50"
    net_tile_count = 1
    quic_tile_count = 1
    verify_tile_count = 1
    resolv_tile_count = 1
    gossvf_tile_count = 1
    execle_tile_count = 1
    execrp_tile_count = 1
    shred_tile_count = 1
    sign_tile_count = 2
    snapshot_hash_tile_count = 1
    snapwr_tile_count = 1

[net]
    interface = "$(ip -o -4 addr show scope global | awk '{print $2}' | head -n1)"

[gossip]
    entrypoints = ["$SERVER_IP:8010"]
    port = 9401

[consensus]
    expected_shred_version = $SHRED_VERSION
    expected_genesis_hash = "$GENESIS_HASH"

[accounts]
    max_accounts = 1_000_000
    file_size_gib = 1
    max_unrooted_account_size_gib = 1
    cache_size_gib = 1
    write_delay_slots = 8

[runtime]
    max_live_slots = 512
    max_fork_width = 4
    [runtime.program_cache]
        heap_size_mib = 512

[snapshots]
    incremental_snapshots = false
    genesis_download = false

[snapshots.sources]
    servers = []
    [snapshots.sources.gossip]
        allow_any = false
        allow_list = []

[tiles]
    [tiles.gui]
        enabled = false
    [tiles.bundle]
        enabled = false

[development]
    sandbox = false
    no_clone = true

    [development.gossip]
        allow_private_address = true

    [development.genesis]
        validate_genesis_hash = false
EOF

echo "Config written to /tmp/fd-localnet.toml"
```

**Config notes:**

- Networking uses XDP by default (the `interface` field selects the NIC). XDP is the production networking mode and is more relevant for security testing. On VMs where XDP is not supported, add `provider = "socket"` to the `[net]` section as a fallback.  
- `max_page_size = "huge"` \-- uses 2 MiB hugepages (compatible with VMs; use `"gigantic"` on bare metal for better performance)  
- `sandbox = false` and `no_clone = true` \-- disables security sandbox for development  
- `validate_genesis_hash = false` \-- required because the local cluster uses a non-standard genesis hash  
- `allow_private_address = true` \-- allows gossip on private/localhost IPs  
- `sign_tile_count` must be \>= 2  
- `affinity = "f50"` \-- all tiles float on available CPU cores (no pinning)  
- The gossip entrypoint must match the Agave gossip port (`8010` when using `agave-cluster`)

**Memory tuning notes (the `[accounts]` and `[runtime]` sections):**

- With the settings above, Firedancer requires \~192 GiB hugepages (98,432 × 2 MiB pages). The dominant cost is the `banks` workspace (\~65 GiB) which uses hardcoded mainnet constants and cannot be reduced via config.  
- `max_accounts = 1_000_000` \-- 1M accounts is plenty for localnet (default 30M is for mainnet's \~1B accounts)  
- `file_size_gib = 1` \-- reduces the in-memory accounts database from 16 GiB to 1 GiB  
- `max_live_slots = 512` \-- must be high enough for FD to catch up from the snapshot to the cluster head and for root to advance (requires 31+ consecutive votes). Do not go below 256 or FD will stall.  
- `runtime.program_cache.heap_size_mib = 512` \-- reduces program cache from 2 GiB to 512 MiB (minimum is 200 MiB)  
- If you have 512+ GB RAM, you can omit these sections and use defaults  
- See [Memory Tuning](http://localnet-memory-tuning.md) for a full breakdown of workspace sizes and why 256 GB RAM is the minimum.

**Snapshot source notes (the `[snapshots.sources]` section):**

- Disabling snapshot download (`allow_any = false`) is required for localnet. In `firedancer-dev` single-process mode, the snapshot contact tile's socket allocation can fail if the file descriptor space is fragmented by other tiles. Since we provide the snapshot as a local file, this is safe to disable.

### 8d. Copy genesis and snapshot

```shell
mkdir -p $FD_HOME/snapshots
chmod 700 $FD_HOME/snapshots

# Copy genesis from Agave
cp $BOOTSTRAP_DIR/genesis.bin $FD_HOME/

# Copy latest snapshot
SNAPSHOT=$(ls -t $BOOTSTRAP_DIR/snapshot-*.tar.zst | head -1)
cp "$SNAPSHOT" $FD_HOME/snapshots/
echo "Copied: $(basename $SNAPSHOT)"
```

**Note:** The `chmod 700` is required \-- Firedancer validates that the snapshots directory has mode `700` and will refuse to start otherwise.

### 8e. Configure system and start

```shell
# Create log file owned by your user (FD drops privileges to the calling user)
rm -f /tmp/firedancer.log
touch /tmp/firedancer.log

# Allow unprivileged ICMP (needed by snapshot contact tile)
sudo sysctl -w net.ipv4.ping_group_range="0 65535"

# Configure hugepages and sysctls
sudo $FD_BIN configure init all --config /tmp/fd-localnet.toml

# Start Firedancer (joins the Agave cluster)
sudo $FD_BIN dev --no-configure --config /tmp/fd-localnet.toml &
```

Wait for Firedancer to catch up. This takes 1-5 minutes as FD replays slots from the snapshot to the cluster head:

```shell
# Monitor catch-up progress
for i in $(seq 1 24); do
  sleep 15
  SLOT_LINE=$(grep "tower_slot_done" /tmp/firedancer.log | tail -1)
  REPLAY=$(echo "$SLOT_LINE" | grep -o "replay_slot=[0-9]*")
  ROOT=$(echo "$SLOT_LINE" | grep -o "root_slot=[0-9]*")
  LEADER=$(echo "$SLOT_LINE" | grep -o "next_leader_slot=[0-9]*")
  echo "[$i] $REPLAY $ROOT $LEADER"
done
```

FD is healthy when:

- `root_slot` starts advancing (no longer `18446744073709551615`)  
- `replay_slot` approaches Agave's current slot  
- `next_leader_slot` shows a real slot number once epoch 2 begins (slot 4096+)

During epoch 1, `next_leader_slot` will show `18446744073709551615` (ULONG\_MAX) — this is expected because FD has no leader slots until epoch 2\. FD will cross the epoch boundary automatically and begin producing blocks at its assigned leader slots in epoch 2\.

**Note:** If you boot FD early in epoch 1 (e.g., when the cluster is at slot 300), you may need to wait \~10 minutes for epoch 2 to start. The cluster advances at \~3 slots/second, so epoch 2 begins roughly `(4096 - current_slot) / 3` seconds after boot.

## 9\. Verify the Cluster

### Check gossip peers

```shell
solana -u http://$SERVER_IP:8899 gossip
```

You should see two validators listed.

### Check validators and stake

```shell
solana -u http://$SERVER_IP:8899 validators
```

### Check slot progression

```shell
solana -u http://$SERVER_IP:8899 slot
sleep 5
solana -u http://$SERVER_IP:8899 slot
```

Slots should be advancing.

## 10\. Submit a Test Transaction

Transactions are submitted through the **Agave RPC** (port 8899). The Firedancer validator processes them via gossip and turbine.

```shell
# Create a test wallet
solana-keygen new --no-bip39-passphrase -o /tmp/test-wallet.json --force

# Fund it from the cluster faucet
solana -u http://$SERVER_IP:8899 transfer \
  -k /tmp/fd-localnet/faucet.json \
  --allow-unfunded-recipient \
  $(solana-keygen pubkey /tmp/test-wallet.json) 10

# Verify
solana -u http://$SERVER_IP:8899 balance /tmp/test-wallet.json
```

### Send a second transaction

```shell
solana-keygen new --no-bip39-passphrase -o /tmp/test-wallet-2.json --force
solana -u http://$SERVER_IP:8899 transfer \
  -k /tmp/test-wallet.json \
  --allow-unfunded-recipient \
  $(solana-keygen pubkey /tmp/test-wallet-2.json) 1

solana -u http://$SERVER_IP:8899 balance /tmp/test-wallet-2.json
# Expected: 1 SOL
```

## 11\. Testing PoC Scenarios

### 11a. Crafted network packet

Send malformed packets directly to Firedancer's gossip, QUIC, shred, or repair ports:

```py
#!/usr/bin/env python3
"""Send a crafted gossip packet to Firedancer."""
import socket

FD_GOSSIP_PORT = 9401  # From config [gossip] port

payload = b"\x00" * 1000  # Replace with your PoC payload

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload, ("127.0.0.1", FD_GOSSIP_PORT))
sock.close()

print(f"Sent {len(payload)} bytes to gossip port {FD_GOSSIP_PORT}")
print("Check /tmp/firedancer.log for crashes or unexpected behavior")
```

### 11b. Malformed transaction

Submit via Agave RPC (Firedancer processes these during its leader slots):

```py
#!/usr/bin/env python3
"""Submit a malformed transaction via RPC."""
import json, requests

SERVER_IP = "SERVER_IP_HERE"  # Replace with your server IP
RPC_URL = f"http://{SERVER_IP}:8899"

malformed_tx_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

resp = requests.post(RPC_URL, json={
    "jsonrpc": "2.0", "id": 1,
    "method": "sendTransaction",
    "params": [malformed_tx_b64, {"encoding": "base64"}]
})
print(json.dumps(resp.json(), indent=2))
```

### 11c. Solfuzz harness testing

For conformance bugs, use the [solfuzz-agave](https://github.com/firedancer-io/solfuzz-agave) harnesses. Accepted targets:

- `instr_execute`, `txn_execute`, `elf_loader`  
- `vm_interp`, `vm_syscall_execute`  
- `shred_parse`, `pack_compute_budget`

### 11d. Bank Hash Mismatch / Consensus PoC

With both validators running, trigger your exploit and check:

```shell
# Watch for bank hash mismatches
grep -i "mismatch\|bank hash\|diverge" /tmp/firedancer.log

# Compare slot progression
echo "Agave: $(solana -u http://$SERVER_IP:8899 slot)"
```

### 11e. Crash / liveness PoC

```shell
# Monitor if Firedancer is still running
while true; do
  if ! pgrep -f "firedancer-dev" > /dev/null; then
    echo "CRASH DETECTED at $(date)"
    tail -50 /tmp/firedancer.log
    break
  fi
  sleep 1
done
```

## 12\. Teardown and Cleanup

```shell
# Stop Firedancer
sudo pkill -f "firedancer-dev"

# Stop Agave cluster
agave-cluster stop-cluster

# Clean up hugepages
sudo $FD_BIN configure fini all --config /tmp/fd-localnet.toml 2>/dev/null

# Remove data
sudo rm -rf $HOME/.firedancer/fd-localnet
rm -rf /tmp/fd-localnet
rm -f /tmp/firedancer.log /tmp/fd-localnet.toml
rm -f /tmp/test-wallet.json /tmp/test-wallet-2.json

# Deactivate agave-cluster env
deactivate_agave_cluster
```

## 13\. Troubleshooting

### Build fails: "incomplete type fd\_dump\_proto\_ctx\_t"

You need to build with `./deps.sh +dev` (not plain `./deps.sh`). The `+dev` flag builds flatcc which is required for protobuf support in the replay tile.

### Build fails: missing system packages

Run `sudo apt install -y autoconf automake autopoint bison flex gcc-multilib gettext libgmp-dev` and re-run `./deps.sh +dev`.

### Firedancer fails to start: hugepage errors

```shell
# Check hugepages
cat /proc/meminfo | grep Huge
# Allocate more if needed
sudo sysctl -w vm.nr_hugepages=10000
```

In VMs, use `max_page_size = "huge"` (not `"gigantic"`).

### Firedancer fails: "sign\_tile\_count must be \>= 2"

The config requires `sign_tile_count = 2` minimum. Don't reduce it below 2\.

### Firedancer fails: topology tile count mismatch

The `affinity` string must provide enough cores for all tiles. Use `f50` (50 floating cores) to be safe, or count the actual tiles needed (typically \~30 with minimal settings).

### Firedancer doesn't catch up / no gossip peers

- Verify the gossip entrypoint IP matches the Agave bootstrap: use `ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1` to get the IP  
- Gossip port for `agave-cluster` is `8010` (not `8001`)  
- Verify shred version matches: `cat /tmp/fd-localnet/cluster-info.txt | grep shred_version`  
- Verify the snapshot was produced *after* stake delegation

### agave-cluster binds to external IP, not localhost

`agave-cluster` binds RPC to the server's external IP. Use `http://<SERVER_IP>:8899` not `http://127.0.0.1:8899`.

### sendTransaction returns HTTP 500 on Firedancer RPC

Firedancer v1.0's RPC has limited write support. Submit transactions via the **Agave RPC** on port 8899\. Firedancer processes them when it receives blocks via turbine/gossip.

### Agave fails: "Unable to increase the maximum open file descriptor limit"

```shell
ulimit -n 1000000
```

For a persistent fix, add to `/etc/security/limits.conf`:

```
* soft nofile 1000000
* hard nofile 1000000
```

Then re-login and retry.

### Agave cluster won't start

```shell
# Check for leftover processes
pgrep -a agave-validator && sudo pkill agave-validator
# Clean and retry
rm -rf /tmp/fd-localnet && mkdir /tmp/fd-localnet
```

### Stake delegation fails: "invalid account data for instruction"

This occurs when using Agave v3.1.11+ because of Vote State V4 (SIMD-0185). The BPF stake program cannot deserialize V4 vote accounts. Fix: apply the patches described in Section 3 (change `--cluster-type` to `development` and deactivate the Vote State V4 feature). See the `sed` commands in Section 3 for the exact fix.

### Firedancer fails to start: ENOMEM hugepage errors with sufficient RAM

Firedancer v1.0 requires \~192 GiB hugepages with the localnet tuning in Section 8c (256 GB RAM minimum). The dominant cost is the `banks` workspace (\~65 GiB) which uses hardcoded mainnet constants and cannot be reduced via configuration. See [Memory Tuning](http://localnet-memory-tuning.md) for a full breakdown. If hugepage allocation fails, ensure previous runs are fully cleaned up: `sudo umount /mnt/.fd/.huge /mnt/.fd/.gigantic 2>/dev/null && sudo rm -rf /mnt/.fd && sudo sysctl vm.nr_hugepages=0`.

### Firedancer stalls at a fixed replay slot

If `max_live_slots` is too small relative to the gap between the snapshot and the cluster head, Firedancer fills all live slot capacity before establishing a root, causing a deadlock. Check with:

```shell
grep "tower_slot_done" /tmp/firedancer.log | tail -5
```

If `root_slot=18446744073709551615` (ULONG\_MAX) and replay\_slot stopped advancing, the snapshot was too far behind the cluster head. You may also see `banks are full and partially executed frontier banks are being evicted` warnings. Fix: kill FD, wait for a fresh snapshot close to the cluster head (within \~200 slots), clean FD state (`sudo rm -rf $FD_HOME/checkpt $FD_HOME/funk $FD_HOME/accounts` and remove old snapshots), copy the new snapshot, and restart. Alternatively, increase `max_live_slots` (note: this significantly increases memory — 512→1024 adds \~69 GiB of hugepages for the banks workspace).

### Firedancer crashes: "FAIL: leaders\[ i \]" in txsend tile

This was a known issue in earlier Firedancer builds where the txsend tile's `FD_TEST( leaders[ i ] )` assertion failed at epoch boundaries when the next epoch's leader schedule hadn't been computed yet. **In Firedancer v1.0, this crash has not been observed** — FD crosses epoch boundaries cleanly when booted from a recent snapshot. If you do encounter this, restart FD from a snapshot produced after the epoch boundary.

### Firedancer crashes: "could not allocate N contiguous sockets"

In `firedancer-dev` single-process mode, the snapshot contact tile needs contiguous file descriptors for TCP sockets. Other tiles can fragment the FD space. Fix: add `[snapshots.sources]` with `allow_any = false` to the config (see Section 8c) to disable snapshot download. The local snapshot file will still be used.

### Agave stuck on "Couldn't vote on heaviest fork: FailedThreshold"

This happens when Firedancer's delinquent stake is large enough to block Agave's supermajority threshold. Fix: use `--sol 10` (not `--sol 100`) when creating FD staked keys, so Agave retains \~64% stake and doesn't need FD's votes for consensus. Do not exceed \~30% stake for FD.

### Snapshot directory permission error

Firedancer requires the snapshots directory to have mode `700`. Fix: `chmod 700 $FD_HOME/snapshots`.

### No snapshots appearing

The Agave bootstrap validator produces full snapshots every 100 slots (\~40 seconds). Check the Agave log:

```shell
tail -100 /tmp/fd-localnet/nodes/node-ledger-0/validator.log | grep -i snapshot
```

## Key Ports and Paths

| Item | Value |
| :---- | :---- |
| Agave RPC | `http://<SERVER_IP>:8899` |
| Agave gossip | `<SERVER_IP>:8010` |
| Firedancer gossip | `9401` |
| Firedancer identity key | `/tmp/fd-localnet/keys/fd-validator/id.json` |
| Firedancer vote key | `/tmp/fd-localnet/keys/fd-validator/vote.json` |
| Firedancer config | `/tmp/fd-localnet.toml` |
| Firedancer log | `/tmp/firedancer.log` |
| Cluster faucet | `/tmp/fd-localnet/faucet.json` |
| Slots per epoch | `2048` (patched from default 256; FD gets leader slots in epoch 2\) |
| Agave version | `v3.1.11` (tested) |
| Firedancer tag | `v1.0` (contest release) |
| In-scope binary | `firedancer` (all reachable code) |
| Build binary | `firedancer-dev` (for local cluster setup) |

# Architecture Overview

# Architecture Overview

# Firedancer v1.0 Localnet: Architecture Overview

Internal reference for how the local test cluster is built and how Firedancer joins.

## Architecture

Single machine running two validators side by side:

- **Agave**: bootstrap validator, holds supermajority stake, provides the RPC for transaction submission  
- **Firedancer v1.0**: joins as a second validator via gossip, receives blocks via turbine, replays and validates them

## How the cluster is built

1. **Genesis creation**: The `agave-cluster` tool (shipped in `contrib/agave-cluster` in the Firedancer repo) generates a genesis block using `solana-genesis` with Firedancer-compatible primordial accounts. It sets cluster type to `mainnet-beta` with short epochs (256 slots) and no inflation.

2. **Agave bootstrap**: The tool starts an Agave validator as the bootstrap node. It's the sole validator initially: 100% of stake, producing all blocks. RPC on port 8899, gossip on port 8010\.

3. **Key creation and staking**: `agave-cluster create-staked-keys` generates identity \+ vote keypairs for Firedancer, funds them from the genesis faucet, creates a vote account, creates a stake account, and delegates stake: all in one command. We stake 100 SOL to the FD validator.

4. **Snapshot**: We wait for Agave to produce a full snapshot *after* the stake delegation (every 100 slots, \~40s). This snapshot contains Firedancer's stake state, which is critical: FD won't recognize itself as a staked validator without it.

## How Firedancer joins

5. **Snapshot boot**: Firedancer loads the Agave snapshot to get the full ledger state at that slot (accounts, bank, program cache). This is how it "catches up" without replaying the entire chain from genesis.

6. **Gossip discovery**: Firedancer connects to Agave's gossip port (`8010`) and announces itself as a validator. Through gossip, both validators exchange contact info (shred/repair/QUIC ports), stake weights, and vote state.

7. **Turbine (shred reception)**: Once gossip is established, Firedancer receives shreds (block fragments) from Agave via turbine. It reassembles them into blocks and replays transactions to advance its local state.

8. **Repair**: If Firedancer misses shreds, it requests them from Agave via the repair protocol.

9. **Voting and block production**: Once Firedancer's stake activates (at an epoch boundary), it participates in consensus by casting votes and producing blocks during its assigned leader slots.

## Transaction flow for PoCs

Researcher submits tx via Agave RPC (port 8899\) \-\> Agave includes it in a block during its leader slot \-\> block is shredded and sent to Firedancer via turbine \-\> Firedancer replays and validates the block \-\> if there's a conformance bug, the bank hashes diverge.

For network-layer PoCs (crafted packets), researchers send directly to Firedancer's gossip (9401), shred, repair, or QUIC ports: no need to go through Agave.

## Resource requirements

- **RAM:** \~192 GB. Firedancer v1.0 pre-allocates \~142 GiB of hugepage-backed workspace memory (accounts DB, funk, banks, tile workspaces) even with minimal tile counts. This is \~5x more than Frankendancer v0.x.  
- **CPU:** 30 tiles (threads) with minimal config. 16 cores recommended.  
- **Disk:** \~100 GB for source builds \+ ledger data.

