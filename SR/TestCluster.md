## Test Cluster (Firedancer & Agave validators)

The test cluster runs in a remote VM accessible via `ssh firedancer`.

Full build/setup instructions: `SR/FiredancerLocalnetSetup.md`

### Quick-start (Agave only, for PoC testing)

The cluster state is ephemeral - it must be restarted after each VM reboot.

```bash
ssh firedancer

# Set up environment
export PATH=$PATH:$HOME/agave/target/release
export FD_DIR=$HOME/firedancer
export AGAVE_DIR=$HOME/agave

# Clean previous state and start fresh
rm -rf /tmp/fd-localnet
mkdir -p /tmp/fd-localnet
cd $FD_DIR/contrib/agave-cluster
source activate $FD_DIR $AGAVE_DIR /tmp/fd-localnet
ulimit -n 1000000

# Start Agave bootstrap cluster (backgrounds automatically)
agave-cluster start-cluster

# Wait for RPC
SERVER_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
while ! curl -s http://$SERVER_IP:8899/health 2>/dev/null | grep -q "ok"; do
  sleep 2
done
echo "RPC ready at http://$SERVER_IP:8899"
solana -u http://$SERVER_IP:8899 slot
```

### Key paths

| Item | Path |
|---|---|
| Agave RPC | http://10.128.0.3:8899 |
| Faucet keypair | /tmp/fd-localnet/faucet.json |
| Agave ledger | /tmp/fd-localnet/nodes/node-ledger-0 |
| Agave log | /tmp/fd-localnet/nodes/node-ledger-0/validator.log |
| FD config | /tmp/fd-localnet.toml |
| FD keys | /tmp/fd-localnet/keys/fd-validator/ |
| FD log | /tmp/firedancer.log |
| solana CLI | ~/agave/target/release/solana |

### Useful commands

```bash
# Always set PATH first
export PATH=$PATH:$HOME/agave/target/release

# Cluster status
solana -u http://10.128.0.3:8899 slot
solana -u http://10.128.0.3:8899 epoch-info
solana -u http://10.128.0.3:8899 gossip
solana -u http://10.128.0.3:8899 validators

# Feature status
solana -u http://10.128.0.3:8899 feature status -um

# Account info
solana -u http://10.128.0.3:8899 account <PUBKEY>

# Fund an account (using faucet)
solana -u http://10.128.0.3:8899 transfer --from /tmp/fd-localnet/faucet.json <DEST> <AMOUNT> --allow-unfunded-recipient

# Check transaction
solana -u http://10.128.0.3:8899 confirm -v <SIGNATURE>
```

### Running Python PoCs

```bash
# From the local machine, copy and run:
scp SR/PoC/my_poc.py firedancer:/tmp/my_poc.py
ssh firedancer 'python3 /tmp/my_poc.py --rpc http://10.128.0.3:8899 --faucet /tmp/fd-localnet/faucet.json'
```

Python deps (`solders`, `solana`, `requests`) are already installed on the VM.

### Adding Firedancer to the cluster

Only needed for consensus/fork-choice PoCs. See FiredancerLocalnetSetup.md sections 7-8. Summary:

```bash
# Create staked keys (run once, after Agave is running)
agave-cluster create-staked-keys --validator-name fd-validator --sol 10

# Wait for recent snapshot, copy genesis + snapshot, then:
sudo $FD_DIR/build/native/gcc/bin/firedancer-dev run --config /tmp/fd-localnet.toml

# FD gets leader slots starting epoch 2 (~20 min from boot)
```

### Notes

- The faucet has ~500M SOL. Use it for funding test accounts.
- The cluster uses 2048 slots/epoch (not the mainnet 432000).
- **Feature set caveat:** The localnet genesis activates 249 features at epoch 0 (almost all features). On mainnet, only a subset are active. Use `solana -u <RPC> feature status` (without `-um`!) to query the localnet. The `-um` flag silently overrides your URL and queries mainnet instead.
- For ZK ElGamal specifically: localnet has `reenable_zk_elgamal_proof_program` active (program fully functional). Mainnet does NOT (program returns "temporarily disabled"). This means localnet is not faithful to mainnet for this program.
- To test mainnet-like feature conditions, you would need to create a custom genesis with specific features excluded, or use `solana feature deactivate` (requires feature authority).
- Simulation via the Python `solana` library often fails with `BlockhashNotFound` on fresh clusters. Use `replaceRecentBlockhash: True` in raw RPC calls, or use `skip_preflight=True` when sending.
