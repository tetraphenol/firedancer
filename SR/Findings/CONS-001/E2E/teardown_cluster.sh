#!/bin/bash
# CONS-001 E2E PoC - Cluster teardown
set -euo pipefail

echo "[*] Stopping validators..."
pkill -f "agave-validator.*cons001" 2>/dev/null || true
pkill -f "firedancer-dev.*cons001" 2>/dev/null || true
# Also catch by config path
pkill -f "fd-config.toml" 2>/dev/null || true
sleep 2
pkill -9 -f "agave-validator.*cons001" 2>/dev/null || true
pkill -9 -f "firedancer-dev.*cons001" 2>/dev/null || true

echo "[*] Cleaning up FD workspaces..."
FD=/home/user/firedancer/build/native/gcc/bin/firedancer-dev
if [ -f /tmp/cons001/fd-config.toml ]; then
    sudo $FD configure fini all --config /tmp/cons001/fd-config.toml 2>/dev/null || true
fi

echo "[*] Removing work directory..."
rm -rf /tmp/cons001

echo "[*] Done."
