# Istio Security POC: Zero-Trust Architecture

This project is a Proof of Concept (POC) demonstrating how an Istio service mesh can provide zero-trust security and decoupled identity passing.

## Demo

Walkthrough of the Istio security POC (login, persona-based access, Cerbos + RLS).

https://github.com/Kaustav-Sarkar/Istio-Defense-In-Depth/raw/main/docs/assets/IstioDemo.mp4

## Architecture

The architecture enforces strict service-to-service authentication (mTLS & AuthZ) and utilizes a sidecar `EnvoyFilter` to securely translate a platform-standard identity header (`x-mesh-identity`) into custom application-specific headers.

For an in-depth explanation of the design, see the [Architecture Document](docs/architecture.md).

## Quickstart (Local Testing)

To run the tests for the currently implemented services:

1. **Run Python Tests**  
   This script runs the `pytest` suites for all existing Python applications.

   ```bash
   ./scripts/test-python.sh
   ```

2. **Run Cerbos Policy Tests**  
   This script runs the Cerbos policy tests.

   ```bash
   ./scripts/test-cerbos.sh
   ```

3. **Run the UI (after cluster is up)**  
   The Streamlit UI runs locally on the host (outside the cluster). Requires `mkcert` (`brew install mkcert nss`).

   ```bash
   ./scripts/create-local-certs.sh   # one-time: generates trusted certs
   ./scripts/run-ui.sh               # starts UI at https://app.localtest.me:8501
   ```

4. **Run the security attack suite (after cluster is up)**  
   Manual negative-path tests across 12 attack categories. See [security-tests/ATTACKS.md](security-tests/ATTACKS.md).

   ```bash
   pip install -r security-tests/requirements.txt
   ./security-tests/run-attacks.sh
   ```

For full local cluster setup and end-to-end validation, see the [Setup and Run Guide](docs/setup-and-run.md).

## Demo users (login & verify)

After the cluster and UI are running ([setup guide](docs/setup-and-run.md)), open **<https://app.localtest.me:8501>**, click **Login**, and use these Keycloak accounts:

| Persona | Username | Password | What to check |
|---------|----------|----------|----------------|
| Employee | `alice.employee` | `alice-password` | Own profile shows full PII/salary; other employees are limited |
| Manager | `mary.manager` | `mary-password` | Direct report (Alice) shows salary band, not exact salary |
| HR Admin | `henry.hradmin` | `henry-password` | HR fields on employees; no IT asset serials |
| IT Admin | `ivan.itadmin` | `ivan-password` | Minimal employee fields; full IT asset access |

## Repository Structure

- `apps/` - FastAPI microservices, Streamlit UI, auth-service, and database seeder
- `cerbos/` - Cerbos policies and tests
- `db/` - PostgreSQL initialization scripts and migrations
- `deployment/` - Kubernetes manifests (base, apps, data, identity, networking, security)
- `docs/` - Architecture and setup documentation
- `kind/` - Kind cluster configuration
- `scripts/` - Automation scripts for cluster management and testing
- `security-tests/` - Security attack suite (12 categories; see ATTACKS.md)
