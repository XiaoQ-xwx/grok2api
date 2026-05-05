# Commit Decision History

> 此文件是 `commits.jsonl` 的人类可读视图，可由工具重生成。
> Canonical store: `commits.jsonl` (JSONL, append-only)

| Date | Context-Id | Commit | Summary | Decisions | Bugs | Risk |
|------|-----------|--------|---------|-----------|------|------|
| 2026-05-05 | f90c9564 | cd6c09c | fix(auth): normalize PostgreSQL URL scheme for asyncpg dialect | Add _normalize_pgsql_url(); align with account backend pattern | NoSuchModuleError: postgres dialect not found — URL scheme mismatch | low |
| 2026-05-05 | 8e591170 | 865c175 | chore: remove unused test suite and pytest config | Remove 7 stale test files + pytest config from pyproject.toml | — | low |
| 2026-05-05 | 60a80da7 | pending | fix(auth): strip sslmode from PostgreSQL URL and build SSL context for asyncpg | Strip sslmode query param; build ssl.SSLContext via connect_args; asyncpg rejects sslmode kwarg | TypeError: connect() got unexpected keyword argument sslmode | low |
