# TXN-001: Transaction Parser Rejects Valid Inputs With Trailing Bytes

**Severity:** Invalid (not remotely exploitable)
**Component:** `src/ballet/txn/fd_txn_parse.c:220`

## Description

`fd_txn_parse` (the convenience macro) rejects transaction byte arrays containing trailing data after the last instruction, while Agave's `bincode::deserialize::<VersionedTransaction>` + `sanitize()` accepts them. The check at line 220 requires exact consumption of all input bytes when `payload_sz_opt==NULL`.

## Root Cause

Design difference: the strict `fd_txn_parse` macro passes `NULL` for `payload_sz_opt`, enforcing no trailing bytes. The lenient `fd_txn_parse_core` with a non-NULL `payload_sz_opt` accepts trailing bytes and reports consumed size.

## Why Invalid

The consensus-critical replay path is not affected. All non-consensus paths handle the divergence gracefully.

**Block replay (consensus-critical):** `fd_sched_parse_txn` (`src/discof/replay/fd_sched.c:2065`) uses the lenient `fd_txn_parse_core` with `&pay_sz`. It accepts trailing bytes, reports consumed size, and advances the buffer offset correctly (line 2136). No divergence from Agave.

**TPU / verify tile:** `src/disco/verify/fd_verify_tile.c:117` uses the strict macro but handles failure gracefully - drops the transaction and increments a metric (line 131-134). No crash, no consensus impact.

**Gossip votes in Firedancer:** In Firedancer's topology (`src/app/firedancer/topology.c:961`), gossip votes flow gossip -> verify -> dedup. There is no direct `gossip_dedup` link (that only exists in Frankendancer). The verify tile extracts transaction bytes with an exact `transaction_len` computed as a pointer delta in `fd_gossip_message.c:181`, so trailing bytes cannot survive extraction. The `FD_LOG_ERR` crash in `fd_dedup_tile.c:188` for `IN_KIND_GOSSIP` is dead code in Firedancer's topology.

**Entry format:** Transactions in blocks are serialized sequentially without per-transaction length prefixes. Both implementations parse field-by-field and advance, so trailing bytes between transactions are structurally impossible.

## Found By

Differential fuzzing: `fuzz_txn_parse_diff` (fd_txn_parse vs bincode VersionedTransaction)
