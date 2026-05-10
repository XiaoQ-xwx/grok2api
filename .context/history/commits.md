# Commit Decision History

> 此文件是 commits.jsonl 的人类可读视图，可由工具重生成。
> Canonical store: commits.jsonl (JSONL, append-only)

| Date | Context-Id | Commit | Summary | Decisions | Bugs | Risk |
|------|-----------|--------|---------|-----------|------|------|
| 2026-05-10 | 63aedbe6 | 95abbbc | fix(webui): resolve LD password verification crash and config indicator gap | PENDING token now always stores user.id (LinuxDo provider int) instead of local_user.id (UUID) to match get_user_by_provider lookup<br>Config page password field uses hasValuePath schema extension to show placeholder when bcrypt hash exists | LD password verification returned 500 Internal server error JSON → Always pass str(user.id) to issue_pending_token — consistent with verify handler which looks up by provider_user_id<br>Config page LD password field always appeared empty even when password was set → Add hasValuePath to field schema; renderInput shows "已设置" placeholder when hash exists | - |
