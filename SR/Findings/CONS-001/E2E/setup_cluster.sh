#!/bin/bash
# CONS-001 E2E PoC - Localnet cluster setup
#
# Uses agave-cluster tool from Firedancer repo to bootstrap a 2-validator
# localnet (Agave + Firedancer). Following SR/FiredancerLocalnetSetup.md.
#
# Creates a dummy third bootstrap validator in genesis so the attacker
# can target its vote account (combined Agave + Dummy = 67% stake > 52%).
#
# Usage: bash setup_cluster.sh    (from the remote host, as the normal user)
# Requires: sudo access, ~200 GiB RAM for hugepages

set -euo pipefail

export FD_DIR="$HOME/firedancer"
export AGAVE_DIR="$HOME/agave"
export FD_BIN="$FD_DIR/build/native/gcc/bin/firedancer-dev"
export PATH="$AGAVE_DIR/target/release:$PATH"

WORKDIR=/tmp/fd-localnet
SERVER_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
IFACE=$(ip -o -4 addr show scope global | awk '{print $2}' | head -n1)

# ---- Cleanup ----
echo "[*] Cleaning previous run..."
sudo pkill -f "firedancer-dev" 2>/dev/null || true
sudo pkill -f "agave-validator" 2>/dev/null || true
sleep 2
sudo rm -rf /mnt/.fd/.huge/fd-localnet* /mnt/.fd/.huge/cons001fd_* 2>/dev/null || true
rm -rf $WORKDIR

# ---- Apply agave-cluster patches ----
echo "[*] Patching agave-cluster for Agave v3.1.11..."
cd $FD_DIR/contrib/agave-cluster/agave_cluster
# Vote State V4 fix + epoch size fix (idempotent via grep guard)
if grep -q '"--cluster-type", "mainnet-beta"' cli.py 2>/dev/null; then
    sed -i 's/"--cluster-type", "mainnet-beta"/"--cluster-type", "development", "--deactivate-feature", "Gx4XFcrVMt4HUvPzTpTSVkdDVgcDSjKhDN1RqRS6KDuZ"/' cli.py
fi
if grep -q '"--slots-per-epoch", "256"' cli.py 2>/dev/null; then
    sed -i 's/"--slots-per-epoch", "256"/"--slots-per-epoch", "2048"/' cli.py
fi

# ---- Start Agave bootstrap cluster ----
echo "[*] Starting Agave bootstrap cluster via agave-cluster..."
mkdir -p $WORKDIR
cd $FD_DIR/contrib/agave-cluster
# activate script checks $AGAVE_CLUSTER_ACTIVE which may be unset
set +u
source activate $FD_DIR $AGAVE_DIR $WORKDIR
set -u

ulimit -n 1000000 2>/dev/null || true
agave-cluster start-cluster

echo "[*] Waiting for Agave RPC at http://$SERVER_IP:8899..."
for i in $(seq 1 60); do
    if curl -s http://$SERVER_IP:8899/health 2>/dev/null | grep -q "ok"; then
        break
    fi
    sleep 2
done
echo "    Agave slot: $(solana -u http://$SERVER_IP:8899 slot 2>/dev/null || echo N/A)"

# ---- Create FD staked keys ----
echo "[*] Creating Firedancer staked keys..."
agave-cluster create-staked-keys --validator-name fd-validator --sol 10

FD_KEYS_DIR="$WORKDIR/keys/fd-validator"
FD_ID=$(solana-keygen pubkey $FD_KEYS_DIR/id.json)
FD_VOTE=$(solana-keygen pubkey $FD_KEYS_DIR/vote.json)
echo "    FD identity: $FD_ID"
echo "    FD vote:     $FD_VOTE"

# ---- Create dummy staked validator for the attack ----
# The dummy never runs but its vote account is in epoch stakes,
# so the attacker can target it. Combined Agave + Dummy > 52%.
echo "[*] Creating dummy staked keys..."
agave-cluster create-staked-keys --validator-name dummy-validator --sol 10

DUMMY_KEYS_DIR="$WORKDIR/keys/dummy-validator"
DUMMY_VOTE=$(solana-keygen pubkey $DUMMY_KEYS_DIR/vote.json)
echo "    Dummy vote:  $DUMMY_VOTE"

# Get Agave vote account
AGAVE_VOTE=$(solana -u http://$SERVER_IP:8899 vote-account-addy 2>/dev/null || \
    solana -u http://$SERVER_IP:8899 validators --output json 2>/dev/null | \
    python3 -c "import sys,json; v=json.load(sys.stdin)['validators']; print(v[0]['voteAccountPubkey'])" 2>/dev/null || \
    echo "unknown")
echo "    Agave vote:  $AGAVE_VOTE"

# If we can't get the Agave vote account from CLI, try from the key file
if [ "$AGAVE_VOTE" = "unknown" ]; then
    AGAVE_VOTE_KEY=$(find $WORKDIR -name "vote.json" -path "*/node-*" | head -1)
    if [ -n "$AGAVE_VOTE_KEY" ]; then
        AGAVE_VOTE=$(solana-keygen pubkey "$AGAVE_VOTE_KEY")
        echo "    Agave vote (from key): $AGAVE_VOTE"
    fi
fi

# ---- Wait for recent snapshot ----
echo "[*] Waiting for a recent snapshot (first one at slot ~100)..."
BOOTSTRAP_DIR="$WORKDIR/nodes/node-ledger-0"
SLOT="none"
for i in $(seq 1 120); do
    CURRENT=$(solana -u http://$SERVER_IP:8899 slot 2>/dev/null || echo "0")
    LATEST=$(ls -t $BOOTSTRAP_DIR/snapshot-*.tar.zst 2>/dev/null | head -1 || true)
    if [ -n "$LATEST" ]; then
        SLOT=$(basename "$LATEST" | sed 's/snapshot-\([0-9]*\)-.*/\1/')
        TARGET=$((CURRENT - 200))
        if [ "$SLOT" -ge "$TARGET" ] 2>/dev/null; then
            echo "    Snapshot at slot $SLOT (cluster at $CURRENT)"
            break
        fi
    fi
    echo "    Waiting... (cluster at $CURRENT, snapshot at ${SLOT})"
    sleep 5
done

# ---- Get cluster parameters ----
GENESIS_HASH=$(solana -u http://$SERVER_IP:8899 genesis-hash)
SHRED_VERSION=$(cat $WORKDIR/cluster-info.txt | grep shred_version | cut -d= -f2)
echo "[*] Genesis: $GENESIS_HASH  Shred: $SHRED_VERSION"

# ---- Write FD config ----
echo "[*] Writing FD config..."
FD_HOME="$HOME/.firedancer/fd-localnet"
mkdir -p $FD_HOME/snapshots
chmod 700 $FD_HOME/snapshots

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
    interface = "$IFACE"

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

# ---- Copy genesis and snapshot ----
echo "[*] Copying genesis and snapshot..."
cp $BOOTSTRAP_DIR/genesis.bin $FD_HOME/
SNAPSHOT=$(ls -t $BOOTSTRAP_DIR/snapshot-*.tar.zst | head -1)
cp "$SNAPSHOT" $FD_HOME/snapshots/
echo "    Copied: $(basename $SNAPSHOT)"

# ---- Pre-allocate hugepages on NUMA node 0 ----
# FD needs ~98k hugepages (196 GiB) total, all on NUMA node 0.
echo "[*] Allocating hugepages on NUMA node 0..."
sudo rm -rf /mnt/.fd/.huge/fd-localnet* 2>/dev/null || true
echo 0 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages > /dev/null 2>&1 || true
echo 0 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages > /dev/null 2>&1 || true
echo 120000 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages > /dev/null
HP_FREE=$(cat /sys/devices/system/node/node0/meminfo | grep HugePages_Free | awk '{print $4}')
echo "    Hugepages free on node 0: $HP_FREE"

# ---- Configure and start FD ----
rm -f /tmp/firedancer.log
touch /tmp/firedancer.log
sudo sysctl -w net.ipv4.ping_group_range="0 65535" >/dev/null 2>&1 || true

echo "[*] Configuring Firedancer (hugepages + sysctls)..."
sudo $FD_BIN configure init all --config /tmp/fd-localnet.toml 2>&1 | tail -3

echo "[*] Starting Firedancer..."
sudo $FD_BIN dev --no-configure --config /tmp/fd-localnet.toml &
FD_PID=$!
echo "    FD PID: $FD_PID"

# ---- Wait for FD to catch up ----
echo "[*] Waiting for FD to catch up (this takes 1-5 minutes)..."
for i in $(seq 1 24); do
    sleep 15
    SLOT_LINE=$(grep "tower_slot_done" /tmp/firedancer.log 2>/dev/null | tail -1)
    if [ -n "$SLOT_LINE" ]; then
        REPLAY=$(echo "$SLOT_LINE" | grep -o "replay_slot=[0-9]*" || true)
        ROOT=$(echo "$SLOT_LINE" | grep -o "root_slot=[0-9]*" || true)
        echo "    [$i] $REPLAY $ROOT"
        # Check if root is advancing (not ULONG_MAX)
        ROOT_VAL=$(echo "$ROOT" | grep -o "[0-9]*" || echo 0)
        if [ "$ROOT_VAL" -gt 0 ] 2>/dev/null && [ "$ROOT_VAL" -lt 18446744073709551615 ] 2>/dev/null; then
            echo "    FD root is advancing - cluster is healthy"
            break
        fi
    else
        echo "    [$i] FD not yet replaying..."
    fi
done

# ---- Print cluster info ----
echo ""
echo "============================================"
echo "  CONS-001 Localnet Cluster Ready"
echo "============================================"
echo ""
echo "Agave RPC:     http://$SERVER_IP:8899"
echo "FD gossip:     $SERVER_IP:9401"
echo ""

# Get FD's TPU ports from gossip
echo "[*] Gossip peers:"
solana -u http://$SERVER_IP:8899 gossip 2>/dev/null || true
echo ""

# Extract FD's TPU port from gossip output
FD_TPU_LINE=$(solana -u http://$SERVER_IP:8899 gossip 2>/dev/null | grep "$FD_ID" || true)
FD_TPU_PORT=$(echo "$FD_TPU_LINE" | awk '{print $4}' || echo "unknown")
FD_TPU_QUIC_PORT=$(echo "$FD_TPU_LINE" | awk '{print $5}' || echo "unknown")
echo "FD TPU (UDP):  $SERVER_IP:$FD_TPU_PORT"
echo "FD TPU (QUIC): $SERVER_IP:$FD_TPU_QUIC_PORT"
echo ""
echo "Agave vote account: $AGAVE_VOTE"
echo "Dummy vote account: $DUMMY_VOTE"
echo "FD vote account:    $FD_VOTE"
echo "FD identity:        $FD_ID"
echo ""
echo "FD log: /tmp/firedancer.log"
echo ""

# Save cluster info for the attack script
cat > $WORKDIR/cluster_info.json << INFOJSON
{
    "rpc_url": "http://$SERVER_IP:8899",
    "fd_tpu_host": "$SERVER_IP",
    "fd_tpu_port": $FD_TPU_PORT,
    "fd_tpu_quic_port": $FD_TPU_QUIC_PORT,
    "agave_vote_account": "$AGAVE_VOTE",
    "dummy_vote_account": "$DUMMY_VOTE",
    "fd_vote_account": "$FD_VOTE",
    "fd_identity": "$FD_ID",
    "fd_log": "/tmp/firedancer.log"
}
INFOJSON

echo "Cluster info saved to $WORKDIR/cluster_info.json"
echo ""
echo "Current slot: $(solana -u http://$SERVER_IP:8899 slot 2>/dev/null || echo N/A)"
solana -u http://$SERVER_IP:8899 epoch-info 2>/dev/null || true
