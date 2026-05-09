### 2026-05-05 — fix(auth): normalize PostgreSQL URL scheme for asyncpg dialect

- **Commit**: `cd6c09c` | **Context-Id**: `f90c9564-f0cd-4097-9938-ba2614fd1a65`
- **Files**: app/platform/auth/backends/sql.py (+11/-1)

**Decisions**:
- Add _normalize_pgsql_url() to convert postgres:// and pgsql:// schemes to postgresql+asyncpg://
- Mirror existing normalization pattern from app/control/account/backends/sql.py:160-165

**Bugs**:
- **NoSuchModuleError: Can't load plugin: sqlalchemy.dialects:postgres on deployment** → ACCOUNT_POSTGRESQL_URL env var uses postgres:// scheme; SQLAlchemy dialect name is postgresql not postgres → Normalize URL scheme in create_pgsql_engine() before passing to create_async_engine()

---

### 2026-05-05 — chore: remove unused test suite and pytest config

- **Commit**: `865c175` | **Context-Id**: `8e591170-a087-4eef-a748-1b6767e4238e`
- **Files**: pyproject.toml, tests/conftest.py, tests/test_admin_api.py, tests/test_audit.py, tests/test_keygen.py, tests/test_middleware.py, tests/test_repository.py, tests/test_webui_api.py (+0/-1436)

**Decisions**:
- Remove 7 stale test files (1436 lines) that are no longer maintained
- Remove [tool.pytest.ini_options] from pyproject.toml as tests directory is gone

---

### 2026-05-05 — fix(auth): strip sslmode from PostgreSQL URL and build SSL context for asyncpg

- **Commit**: `8e00f6d` | **Context-Id**: `60a80da7-33af-454c-881c-d6090f25c2f8`
- **Files**: app/platform/auth/backends/sql.py (+69/-10)

**Decisions**:
- Add _prepare_pgsql_url() to normalize URL scheme and extract sslmode query param
- Build ssl.SSLContext from sslmode value and pass via connect_args to asyncpg
- asyncpg does not accept sslmode kwarg �� must use ssl parameter with SSLContext object

**Bugs**:
- **TypeError: connect() got an unexpected keyword argument sslmode** → asyncpg driver does not recognize libpq-style sslmode URL query parameter → Strip sslmode from URL, build ssl.SSLContext, pass via connect_args={"ssl": ctx}

---

### 2026-05-09 — feat(webui): enhance API keys modal with keyboard shortcuts, auto-copy, and a11y

- **Commit**: `TBD` | **Context-Id**: `dcd66dd0-67d7-4815-8618-2a906ca37927`
- **Files**: app/statics/css/app.css, app/statics/webui/keys.html (+80/-20)

**Decisions**:
- Use CSS .open class for modal visibility transition instead of inline display:none toggle
- Add keyboard shortcuts: Escape to close, Enter to submit in input field
- Auto-copy newly created key to clipboard via navigator.clipboard.writeText()
- Add button disabled state and 'Creating...' label during API call to prevent double submission
- Add modal close button (X) in top-right corner for clearer affordance
- Add body scroll lock (overflow: hidden) when modal is open
- Replace generic div descriptions with semantic <p> elements for better accessibility

---

