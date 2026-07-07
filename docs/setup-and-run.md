# Istio Security POC: Setup and Run Guide

This guide provides step-by-step instructions to bootstrap the local cluster, deploy the zero-trust architecture, and validate its security controls.

## Prerequisites
- Docker or Colima running
- `kind`, `kubectl`, `istioctl`, `jq`, `curl` installed
- `mkcert` and `nss` for local TLS certificates (`brew install mkcert nss`)

## 1. Environment Setup

### 1.1 Clean Start
If you have an existing cluster, destroy it first:
```bash
./scripts/destroy-kind-cluster.sh
```

### 1.2 Local TLS Setup (mkcert)

This project uses `mkcert` to generate locally-trusted TLS certificates. Unlike self-signed OpenSSL certs, `mkcert` installs a local Certificate Authority into your system trust store so that:

- **Browsers** (Chrome, Safari, Firefox via `nss`) trust the certs with no security warnings
- **Python's `requests`** library (via `certifi`) trusts them with default `verify=True`
- **`curl`** works without `--insecure`

The script generates certs for two domains (all resolve to `127.0.0.1` via `localtest.me`):

| Domain | Purpose | Where cert is used |
|--------|---------|-------------------|
| `app.localtest.me` | Istio Ingress Gateway (API + auth) & UI | K8s TLS secret in `istio-system` & Local filesystem |
| `idp.localtest.me` | Keycloak OIDC/SAML protocol surface | K8s TLS secret in `istio-system` |

```bash
./scripts/create-local-certs.sh
```

This runs `mkcert -install` (idempotent — safe to re-run) and generates certs in `.local/certs/`.

### 1.3 Create Cluster & Platform
```bash
./scripts/bootstrap-tools.sh
./scripts/create-kind-cluster.sh
```

Note: `create-kind-cluster.sh` calls `create-local-certs.sh` internally, so if you already ran it in 1.2, certs will be reused.

### 1.4 Build and Load Images
```bash
./scripts/build-images.sh
./scripts/load-images-kind.sh
```

### 1.5 Deploy Platform & Apps
```bash
./scripts/deploy-platform.sh
./scripts/deploy-apps.sh
./scripts/wait-for-ready.sh
```

### 1.6 Seed the Database
Deploy the seeder job to populate the database with test data:
```bash
kubectl apply -f deployment/apps/db-seeder-job.yaml
kubectl wait --for=condition=complete job/db-seeder -n zt-apps --timeout=60s
```

### 1.7 After cluster restart: Vault re-bootstrap (expected for POC)

The local Vault deployment uses file storage with Shamir sealing. **Every time the Vault process restarts** (for example after stopping Docker, restarting the kind node, or rescheduling the Vault pod), Vault comes back **sealed**. The one-shot `vault-bootstrap` job only unseals on first init; it does not run again while the Job stays `Completed`.

**Symptoms**

- You are logged in (`/auth/session` works) but profile queries in the UI fail with **403**.
- `GET /api/offices` may still work (that route bypasses ExtAuthz entirely).
- auth-service logs show `500` on `/verify/api/profile/...`.

**Check**

```bash
kubectl port-forward -n zt-security svc/vault 8200:8200 &
sleep 1
curl -s http://127.0.0.1:8200/v1/sys/health | jq '.sealed'
kill %1
```

If the output is `true`, Vault is sealed and mesh token signing is blocked.

**Recovery** (re-run bootstrap and refresh auth-service):

```bash
kubectl delete job vault-bootstrap -n zt-security --ignore-not-found
kubectl delete pod -l app=vault -n zt-security
kubectl wait --for=condition=ready pod -l app=vault -n zt-security --timeout=120s

kubectl apply -f deployment/security-services/vault-bootstrap-job.yaml
kubectl wait --for=condition=complete job/vault-bootstrap -n zt-security --timeout=300s

kubectl rollout restart deploy/auth-service -n zt-apps
kubectl rollout status deploy/auth-service -n zt-apps --timeout=120s
```

Confirm Vault is unsealed (`"sealed": false` in `/v1/sys/health`), then retry the profile query in the UI.

**Note:** Deleting the Vault pod wipes its `emptyDir` data. Re-bootstrap re-initializes Vault and issues a new auth-service token in `vault-auth-token`. This is acceptable for the POC; production would use persistent storage and an automated unseal strategy (see `docs/architecture.md`).

## 2. Interactive Demo Scenarios

### 2.1 Run the UI Dashboard

The Streamlit UI runs **outside the cluster** as a local process on your machine. This is intentional — it acts as a true external client, proving the Zero-Trust boundary works correctly. All its requests enter the cluster through the Istio Ingress Gateway, just like a browser or `curl` would.

```bash
./scripts/run-ui.sh
```

This script:
1. Checks that `app.localtest.me` certificates exist (from `create-local-certs.sh`)
2. Creates/activates a Python venv in `apps/ui-dashboard/`
3. Installs dependencies
4. Launches Streamlit with TLS using the `app.localtest.me` cert

**Access:** `https://app.localtest.me:8501` (or visit `https://app.localtest.me` to be redirected)
**Backend API:** The UI calls `https://app.localtest.me` (the Istio Gateway)

Since `app.localtest.me` uses `mkcert`-issued certificates trusted by your system, the browser trusts it without warnings, and the UI's Python `requests` calls to the gateway work with default `verify=True`.

### 2.2 Role-Based Masking (Cerbos & RLS)
Demonstrate how different roles see different data shapes for the same API.

1. **Employee View:**
   - Click "Login" and authenticate as `alice.employee` (password: `alice-password`).
   - Check "My Profile (Session User)". Alice sees all her own info (including base salary, SSN) and her hardware assets.
   - Check another employee (e.g., "Ivan"). Alice sees their public info only (name, title, department) and no IT assets.
   - Click "Logout".

2. **Manager View:**
   - Login as `mary.manager` (password: `mary-password`).
   - Check "My Profile (Session User)". Mary sees all her own info.
   - Check a direct report (e.g., "Alice"). Mary sees the manager view (includes salary band but no exact base salary or SSN).
   - Click "Logout".

3. **HR Admin View:**
   - Login as `henry.hradmin` (password: `henry-password`).
   - Check any employee. Henry sees full HR info (including SSN and salary band, but no exact base salary) but NO IT devices.
   - Click "Logout".

4. **IT Admin View:**
   - Login as `ivan.itadmin` (password: `ivan-password`).
   - Check any employee. Ivan sees basic barebones info (no salary, no SSN) but has FULL access to ALL IT assets (full serial numbers).
   - Click "Logout".

### 2.3 Public Data Routes

Office locations and holidays are both “company-wide” data, but the gateway treats them differently:

1. **`/api/offices` (no login):**
   - Navigate to `https://app.localtest.me/api/offices` without logging in.
   - Observe a **200** response with office data. The gateway `AuthorizationPolicy` skips ExtAuthz for all methods on this path; ms5 assigns an anonymous/public Cerbos context.

2. **`/api/holidays` (login required):**
   - Navigate to `https://app.localtest.me/api/holidays` without logging in.
   - Observe **401 Unauthorized** — ExtAuthz requires a valid session or bearer token for this route.

3. **After login:**
   - Login as any user (e.g., `alice.employee` / `alice-password`).
   - `/api/holidays` returns data with role-appropriate visibility (Cerbos + RLS). `/api/offices` remains publicly readable at the gateway; write operations are gated inside ms5.

## 3. Automated Validation

### 3.1 Run Negative Path Tests
These tests prove that the system denies unauthorized access, spoofed headers, and direct backend access.
```bash
./scripts/test-security-negative-paths.sh
```

### 3.2 Run Header Projection Tests
Demonstrate that the mesh successfully projects the validated `x-mesh-identity` into the legacy app-specific headers.
```bash
./scripts/test-header-projection.sh
```

### 3.3 Run Vault Key Rotation
Demonstrate that the system can rotate the Vault Transit key and that old tokens eventually expire.
```bash
./scripts/test-vault-rotation.sh
```

To perform an operational key rotation (rotate + invalidate old versions):
```bash
./scripts/rotate-vault-key.sh          # immediate invalidation
./scripts/rotate-vault-key.sh --grace  # wait 5 min for in-flight tokens to expire first
```

### 3.4 Run RLS Tests
Demonstrate that PostgreSQL Row-Level Security blocks unauthorized data access even if application logic is bypassed.
```bash
./scripts/test-rls.sh
```

### 3.5 Run E2E Smoke Tests
Run basic end-to-end happy path validation.
```bash
./scripts/test-e2e-smoke.sh
```

### 3.6 Run Security Attack Suite (optional)

Manual structured attacks across 12 categories (header spoofing, JWT attacks, path normalization, mTLS checks, static analysis, etc.).

**Prerequisites:** cluster deployed and ready; `jq`, `curl`, `kubectl`, `python3`, `istioctl`.

```bash
pip install -r security-tests/requirements.txt
./security-tests/run-attacks.sh                     # all categories
./security-tests/run-attacks.sh 01 04 08            # by number
./security-tests/run-attacks.sh header-spoofing     # by slug
```

Category reference: [security-tests/ATTACKS.md](../security-tests/ATTACKS.md).

Reports are written to `security-tests/reports/attack-report-<timestamp>.md` (gitignored).

## 4. Teardown
Clean up the local environment:
```bash
./scripts/destroy-kind-cluster.sh
```
