# Testing Strategy

How the project is tested at each layer: unit tests, integration tests with real Postgres, Cerbos policy tests, and cluster-level E2E security validation.

---

## Test Layers Overview

```mermaid
flowchart TD
    subgraph "Layer 1: Unit Tests (per service, fast, no infra)"
        UT1[auth-service unit tests<br/>Mocked DB, mocked Keycloak/Vault]
        UT2[ms1 tests<br/>Mocked downstream via respx]
    end

    subgraph "Layer 2: Integration Tests (real Postgres, testcontainers)"
        IT1[ms2/ms3/ms4/ms5 tests<br/>Real DB with migrations + RLS<br/>Mocked Cerbos]
    end

    subgraph "Layer 3: Policy Tests (Cerbos offline)"
        PT1[Cerbos policy test suite<br/>YAML principals/resources/expected]
    end

    subgraph "Layer 4: Cluster E2E (full Kind cluster)"
        E2E1[test-e2e-smoke.sh<br/>Gateway routes, JWKS, login redirect]
        E2E2[test-security-negative-paths.sh<br/>Spoofed headers, wrong aud, expired tokens]
        E2E3[test-rls.sh<br/>RLS enforcement via psql]
        E2E4[test-vault-rotation.sh<br/>Key rotation + kid change verification]
        E2E5[test-header-projection.sh<br/>Spoofed header rejection]
    end

    UT1 --> IT1 --> PT1 --> E2E1
```

---

## Layer 1: Unit Tests

### auth-service (`apps/auth-service/tests/`)

**Pattern**: Sync FastAPI TestClient + mocked dependencies via `unittest.mock`.

```python
# conftest.py — sets dummy env vars, provides TestClient
os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost/db"
os.environ["KEYCLOAK_URL"] = "http://localhost:8080"
os.environ["VAULT_URL"] = "http://localhost:8200"
os.environ["VAULT_TOKEN"] = "test-token"

@pytest.fixture
def client():
    return TestClient(app)
```

**What's tested**:
- ExtAuthz decision logic (bearer allowed, cookie allowed, no auth denied, wrong role denied)
- OAuth state generation and verification
- Session creation, retrieval, expiry, revocation
- Mesh token minting (mocked Vault)
- JWKS formatting (mocked Vault keys)
- OIDC validation flow (mocked Keycloak JWKS)
- `/verify` path normalization

**Mocking approach**: External calls (Keycloak, Vault, PostgreSQL) are mocked with `@patch`. Tests validate the logic in isolation without any network or DB.

### ms1-profile-aggregator (`apps/ms1-profile-aggregator/tests/`)

**Pattern**: Async `httpx.AsyncClient` + `respx` for mocking downstream HTTP calls.

```python
@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
```

**What's tested**:
- Happy path: all 4 downstream calls succeed, aggregated response correct
- MS2 returns 404 → propagated as 404
- MS2 returns 500 → propagated as 502
- MS3 returns 500 → graceful degradation (partial response, no error)
- MS2 timeout → 502
- MS3 timeout → graceful degradation
- Missing headers → 401
- Schema contract enforcement (validates respx mocks match real Pydantic schemas)

**Key technique**: respx mocks are validated against the actual downstream Pydantic schemas (`EmployeeResponse`, `HardwareAssetResponse`) imported from the sibling services. This catches schema drift between services.

```python
_ms2_schemas = _load_schemas("ms1_tests_ms2_schemas", "ms2-employee-details/schemas.py")
EmployeeResponse = _ms2_schemas.EmployeeResponse
```

---

## Layer 2: Integration Tests (Testcontainers)

### Setup (`apps/conftest.py` — shared across all services)

```mermaid
flowchart TD
    A[pytest session starts]
    B[Spin up PostgresContainer<br/>postgres:15-alpine, db=hr_directory]
    C[Create async engine<br/>postgresql+asyncpg://...]
    D[Run all migration SQL files<br/>001_base_schemas.sql<br/>002_auth_schema.sql<br/>003_runtime_roles.sql]
    E[Test function starts]
    F[Create connection + BEGIN transaction]
    G[Create session bound to connection<br/>join_transaction_mode=create_savepoint]
    H[Test runs with real DB]
    I[ROLLBACK transaction<br/>All test data gone]
    J[Next test]

    A --> B --> C --> D --> E --> F --> G --> H --> I --> J
    J --> E
```

**Key fixtures**:

| Fixture | Scope | Purpose |
|---------|-------|---------|
| `postgres_container` | session | One Postgres container for all tests |
| `db_engine` | session | Async SQLAlchemy engine + schema bootstrap |
| `db_session` | function | Transactional session that rolls back after each test |
| `client` | session (loop_scope) | httpx AsyncClient bound to the FastAPI app with DB override |

### Transactional Isolation

Each test gets a database session wrapped in a transaction that **rolls back** at the end:

```python
@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    connection = await db_engine.connect()
    transaction = await connection.begin()

    async_session_factory = async_sessionmaker(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    session = async_session_factory()
    try:
        yield session
    finally:
        await session.close()
        await transaction.rollback()
        await connection.close()
```

This means:
- Tests can INSERT/UPDATE/DELETE freely
- No test pollutes another test's state
- No manual cleanup needed
- One container serves the entire test session (fast)

### Per-Service conftest (`apps/ms2-employee-details/tests/conftest.py`)

Overrides the app's `get_db` dependency to use the test session:

```python
@pytest_asyncio.fixture(loop_scope="session")
async def client(db_session):
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
```

### Cerbos Mocking in Integration Tests

Default: auto-allow everything (so CRUD tests work without Cerbos running):

```python
@pytest.fixture(autouse=True)
def default_cerbos_allow(monkeypatch):
    async def _allow(*args, **kwargs):
        return {"allowed": True, "outputs": {}}
    monkeypatch.setattr("main.check_cerbos", _allow)
```

Specific tests override with `patch("main.check_cerbos")` to test masking outputs or deny paths.

### What Integration Tests Cover

| Service | Tests |
|---------|-------|
| ms2 | CRUD for employees, PII, financials. Masking with specific `visible_fields`. Request-id forwarding to Cerbos. Role enforcement on writes. |
| ms3 | CRUD for hardware assets. Serial number masking modes. Owner-based filtering. |
| ms4 | Holiday CRUD. Admin role enforcement. Cerbos deny paths. |
| ms5 | Office CRUD. Admin role enforcement. Cerbos deny paths. |

---

## Layer 3: Cerbos Policy Tests

Cerbos has its own offline test runner. No cluster needed.

### Test Suite (`cerbos/tests/test_suite_test.yaml`)

```yaml
principals:
  alice:
    id: alice.employee
    roles: [employee]
  mary:
    id: mary.manager
    roles: [employee, manager]
  henry:
    id: henry.hradmin
    roles: [employee, hr_admin]
  ivan:
    id: ivan.itadmin
    roles: [employee, it_admin]

resources:
  alice_profile:
    kind: employee_profile
    id: alice.employee
    attr:
      id: alice.employee
      manager_id: mary.manager
```

### Expected Results Matrix

| Principal | Resource | view | view_sensitive | update |
|-----------|----------|------|----------------|--------|
| alice | alice_profile | ALLOW | ALLOW (self) | ALLOW (self) |
| alice | mary_profile | ALLOW | DENY | DENY |
| mary | alice_profile | ALLOW | ALLOW (manager) | DENY |
| henry | alice_profile | ALLOW | ALLOW (hr_admin) | ALLOW |

### How to Run

```bash
./scripts/test-cerbos.sh
# Runs: docker run cerbos compile /work/policies --tests /work/tests
```

No cluster, no network — just validates policies against expected outcomes offline.

---

## Layer 4: Cluster E2E Tests

These run against a live Kind cluster with all components deployed.

### test-e2e-smoke.sh — Basic Connectivity

Verifies the deployment is functional:
- Gateway health endpoint returns 200
- `/auth/login` redirects to `idp.localtest.me`
- Keycloak OIDC discovery endpoint accessible
- JWKS endpoint returns 200

### test-security-negative-paths.sh — Security Invariant Verification

The most important test script. Proves the security claims:

```mermaid
flowchart TD
    T1[Unauthenticated request → denied]
    T2[Spoofed headers from outside → denied<br/>x-ms1-user, x-mesh-identity, x-platform-*]
    T3[Direct Tier 2 path via gateway → 404/denied<br/>/api/employees not routed]
    T4[Non-MS1 pod → MS2 → denied by AuthzPolicy]
    T5[Valid token with wrong audience → denied]
    T6[Expired token → denied]
    T7[MS1 → PostgreSQL direct → denied by AuthzPolicy]
    T8[auth-service down → fail closed (503/401)]
```

Key tests:

| Test | How | Proves |
|------|-----|--------|
| Spoofed headers | curl with `x-ms1-user: attacker` | Gateway pre-strip works |
| Non-MS1 to MS2 | kubectl run ephemeral curl pod | AuthorizationPolicy source principal check |
| Wrong audience | Mint token for ms4, send to ms2 | `aud` claim enforcement |
| Expired token | Vault-sign a token with `exp` in the past | Token expiry enforcement |
| MS1 DB access | kubectl run psql pod with ms1 SA | Network policy denies ms1→postgres |
| Fail closed | Scale auth-service to 0, attempt request | ExtAuthz timeout = deny |

### test-rls.sh — Database Row-Level Security

Proves RLS works at the PostgreSQL level:

1. Seed a row as the superuser (bypasses RLS)
2. Query as `ms2_app` WITHOUT `set_config` → **zero rows** (no context = no visibility)
3. Query as `ms2_app` WITH matching `set_config` → **one row** (correct context = visible)

### test-vault-rotation.sh — Key Rotation

Proves key rotation works end-to-end:

1. Get a Keycloak token for alice
2. Mint mesh token 1 → extract `kid`
3. Rotate Vault Transit key
4. Mint mesh token 2 → extract `kid`
5. Assert `kid` changed

### test-header-projection.sh — Header Spoofing

Sends a request with spoofed `x-ms1-user: attacker` + `x-ms1-role: admin` and verifies the gateway rejects it (pre-strip removes them, ExtAuthz has no valid auth).

Run manually after cluster deploy (see [setup-and-run.md](../setup-and-run.md)).

---

## Layer 5 (optional): security-tests

A separate manual attack catalog under `security-tests/` with 12 categories (header spoofing, JWT attacks, token replay, path normalization, SSRF, debug endpoints, RLS scope leak, extauthz behavior, Cerbos attribute spoofing, mTLS enforcement, static analysis, Istio config audit).

| Property | Value |
|----------|-------|
| **When** | After full cluster deploy; complements `test-security-negative-paths.sh` with broader, categorized variants |
| **How** | `pip install -r security-tests/requirements.txt` then `./security-tests/run-attacks.sh` |
| **Reference** | [security-tests/ATTACKS.md](../../security-tests/ATTACKS.md) |
| **Output** | Markdown reports in `security-tests/reports/` (gitignored) |

---

## Test Execution

### Local (unit + integration)

```bash
# All services
./scripts/test-python.sh

# Single service
cd apps/ms2-employee-details
source venv/bin/activate
pytest tests/

# Specific test
pytest tests/test_main.py -k "test_get_employee_pii"
```

### Cerbos policies (no cluster needed)

```bash
./scripts/test-cerbos.sh
```

### Full cluster E2E (requires Kind cluster running)

```bash
./scripts/test-e2e-smoke.sh
./scripts/test-security-negative-paths.sh
./scripts/test-rls.sh
./scripts/test-vault-rotation.sh
./scripts/test-header-projection.sh

# Optional manual attack suite
pip install -r security-tests/requirements.txt
./security-tests/run-attacks.sh
```

---

## Testing Patterns & Conventions

### Dependency Override Pattern

All services use FastAPI's `dependency_overrides` to inject test DB sessions:

```python
app.dependency_overrides[get_db] = _override_get_db
```

This means the app code never knows it's running in a test. Same code path, different database.

### Cerbos Mock Layering

```
Default (autouse fixture): allow all → tests CRUD without Cerbos
Specific test (patch): control outputs → test masking logic
Deny test (patch returns allowed=False): test 403 path
```

### respx for Downstream HTTP

MS1 uses `respx` to mock downstream services. Mocks are validated against real Pydantic schemas:

```python
# This ensures our mocks match reality
emp = EmployeeResponse(id=emp_uuid, first_name="John", ...)
respx_mock.get(url).mock(return_value=httpx.Response(200, content=emp.model_dump_json()))
```

If the downstream schema changes (e.g., renames a field), the test fails at mock construction time — before the HTTP call.

### Transactional Rollback for Isolation

Every integration test runs inside a transaction that's rolled back. Benefits:
- Tests are order-independent
- Parallel test execution is safe (each gets its own transaction)
- No teardown fixtures needed
- Migrations run once per session (fast)

### RLS Testing Strategy

RLS is tested at two levels:
1. **Database level** (`test-rls.sh`): Raw psql proves PostgreSQL enforces policies regardless of application logic.
2. **Application level** (integration tests): Tests set up data and verify the correct rows/fields come back based on the mocked Cerbos outputs.

The integration tests don't exercise RLS directly (they use a superuser-like test connection). The E2E `test-rls.sh` script proves RLS works at the database layer independently.

---

## What's NOT Tested (Gaps)

| Gap | Risk | Why it's acceptable for POC |
|-----|------|---------------------------|
| Mesh token signature round-trip (mint → verify via JWKS) | JWT structure drift | Covered by E2E (token is minted and used in cluster) |
| OAuth state replay (double-use same state) | Logic bug in atomic consumption | `FOR UPDATE` + `consumed_at` is a standard pattern |
| Session expiry edge cases in unit tests | Expired session accepted | `get_session()` checks are simple timestamp comparisons |
| Masking edge cases (salary=0, None) | Wrong salary band displayed | Low blast radius, caught by visual testing |
| Concurrent ExtAuthz load | Thread pool exhaustion | auth-service is sync; known limitation documented |
