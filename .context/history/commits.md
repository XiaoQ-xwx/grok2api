# Commit Decision History

> 此文件是 `commits.jsonl` 的人类可读视图，可由工具重生成。
> Canonical store: `commits.jsonl` (JSONL, append-only)

| Date | Context-Id | Commit | Summary | Decisions | Bugs | Risk |
|------|-----------|--------|---------|-----------|------|------|
| 2026-05-05 | f90c9564 | pending | fix(auth): normalize PostgreSQL URL scheme for asyncpg dialect | Add _normalize_pgsql_url(); align with account backend pattern | NoSuchModuleError: postgres dialect not found — URL scheme mismatch | low |
