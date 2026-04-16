# TXN-002: Transaction Parser Enforces MAX_TX_ACCOUNT_LOCKS at Parse Time

**Severity:** Invalid (not consensus-relevant)
**Component:** `src/ballet/txn/fd_txn_parse.c:113,203-204,222`

## Description

`fd_txn_parse` enforces `total_accounts <= FD_TXN_ACCT_ADDR_MAX (128)` at parse time. Agave's `bincode::deserialize::<VersionedTransaction> + sanitize()` accepts transactions with up to 256 total accounts (Agave's parse-time limit, per `solana-message/v0/mod.rs:154-158`). This produces systematic `fd=0, agave=1` divergences for any transaction with `128 < total_accounts <= 256`.

For V0 transactions, the check at line 203 fails: `writable_cnt <= FD_TXN_ACCT_ADDR_MAX - acct_addr_cnt`. For legacy transactions, the check at line 113 fails: `acct_addr_cnt <= FD_TXN_ACCT_ADDR_MAX`.

## Why Invalid

**No valid block can contain >128-account transactions.** Agave enforces `MAX_TX_ACCOUNT_LOCKS = 128` in `Bank::get_transaction_account_lock_limit()` during batch scheduling before block production. No block is ever produced containing transactions that exceed this limit. Since the divergence only manifests on inputs that cannot appear in valid blocks, it is not consensus-relevant.

**Block replay path is unaffected.** Replay only processes transactions from valid blocks, which never contain >128-account transactions.

**Agave's parse does defer this check.** Agave validates the 128-account limit at execution time (via `SanitizedTransaction::get_account_locks`), not during `VersionedTransaction::sanitize()`. But since block production enforces the limit, this deferral has no practical effect.

## Affected Checks

- Legacy: `acct_addr_cnt > FD_TXN_ACCT_ADDR_MAX` (line 113)
- V0 per-ATL: `writable_cnt > FD_TXN_ACCT_ADDR_MAX - acct_addr_cnt` (line 203)
- V0 per-ATL: `readonly_cnt > FD_TXN_ACCT_ADDR_MAX - acct_addr_cnt` (line 204)
- V0 total: `acct_addr_cnt + addr_table_adtl_cnt > FD_TXN_ACCT_ADDR_MAX` (line 222)

## Found By

Differential fuzzing: `fuzz_txn_parse_diff`. Filtered from harness via `fd_txn_count_accounts` helper that computes total accounts without applying the limit.
