# Security Attack Test Categories

Reference document for all 12 attack categories in the security testing module.

## Usage

```bash
./security-tests/run-attacks.sh                     # all 12 categories
./security-tests/run-attacks.sh 01 04 08            # by number
./security-tests/run-attacks.sh header-spoofing     # by slug
```

## Prerequisites

- Running Kind cluster with full deployment (`./scripts/deploy-apps.sh` completed)
- Tools: kubectl, jq, python3, curl, istioctl
- Python packages: `pip install -r security-tests/requirements.txt`

---

## Category 01: Header Spoofing Past EnvoyFilter

Tests the gateway Lua prestrip filter (`deployment/networking/envoyfilter-gateway-prestrip.yaml`) and per-sidecar projection filters.

| Variant | Attack Vector | SECURE | VULNERABLE |
|---------|--------------|--------|-----------|
| unauthenticated-plain-spoof | `x-ms1-user: attacker` to gateway | 401/403 | 200 |
| case-variation-spoof | `X-MS1-USER: attacker` uppercase | 401/403 | 200 |
| x-mesh-identity-forged-no-sig | alg:none token as header | 401/403 | 200 |
| x-platform-user-spoof | `x-platform-user: attacker` | 401/403 | 200 |
| duplicate-header-one-cased | Two x-mesh-identity headers, different case | 401/403 | 200 |
| in-cluster-direct-injection | kubectl run → ms2 with spoofed x-ms2-user | 401/403 | 200 |
| in-cluster-mesh-identity-alg-none | kubectl run → ms2 with forged x-mesh-identity | 401/403 | 200 |

**Controls tested:** EnvoyFilter Lua script, RequestAuthentication JWT validation, AuthorizationPolicy identity checks.

---

## Category 02: JWT Attack Playbook

Forges malformed JWTs and submits to services via kubectl exec inside the mesh.

| Variant | Attack | SECURE | VULNERABLE |
|---------|--------|--------|-----------|
| alg-none | Strip signature, set alg=none | 401 | 200 |
| rs256-to-hs256 | Sign with public key as HMAC secret | 401 | 200 |
| kid-path-traversal | kid=../../../../dev/null | 401 | 200 |
| kid-sql-injection | kid=1 OR 1=1 | 401 | 200 |
| jwk-header-injection | Embed attacker JWK in token header | 401 | 200 |
| expired-token | exp in the past | 401 | 200 |
| wrong-audience | aud=ms3 submitted to ms2 | 403 | 200 |
| wrong-act-sub | act.sub != ms1-profile-aggregator | 403 | 200 |

**Controls tested:** Istio RequestAuthentication, JWT signature verification, claims validation.

---

## Category 03: Token Replay / Key Rotation

Performs a complete rotation procedure (rotate + bump `min_decryption_version`) and verifies old tokens are invalidated.

| Variant | SECURE | VULNERABLE |
|---------|--------|-----------|
| replay-after-rotation-old-key | 401 (old key rejected or accepted only during JWKS cache window) | 200 (old key permanently accepted) |
| min-decryption-version-check | min >= latest | min=1 with multiple versions |
| token-expiry-enforcement | 401 for expired | 200 for expired |
| jti-uniqueness | Unique jti per token | Duplicate jti values |

**Controls tested:** Vault Transit key lifecycle (`min_decryption_version` management), JWKS key pruning, token expiry enforcement, replay detection.

**Operational script:** `./scripts/rotate-vault-key.sh`

---

## Category 04: AuthorizationPolicy Path Normalization

| Variant | Path | SECURE | VULNERABLE |
|---------|------|--------|-----------|
| double-slash | `/api//profile/<uuid>` | 401/403/404 | 200 |
| percent-encoded-slash | `/api%2fprofile/<uuid>` | 401/403/404 | 200 |
| path-traversal | `/api/offices/../profile/<uuid>` | 401/403/404 | 200 |
| case-variation | `/API/profile/<uuid>` | 401/403/404 | 200 |
| semicolon-injection | `/api/profile;x/<uuid>` | 401/403/404 | 200 |
| tab-in-path | `/api/profile%09/<uuid>` | 401/403/404 | 200 |
| null-byte | `/api/profile%00/<uuid>` | 401/403/404 | 200 |
| method-override | GET + X-HTTP-Method-Override: POST | ignored | server error |

**Controls tested:** Envoy path normalization, AuthorizationPolicy path matching.

---

## Category 05: SSRF

| Variant | Target | SECURE | VULNERABLE |
|---------|--------|--------|-----------|
| uuid-param-injection | Path traversal in profile ID | 422/404 | 200 |
| uuid-encoded-slash | URL-encoded escape attempt | 422/404 | 200 |
| internal-vault-from-ephemeral | curl vault from random pod | 403/timeout | 200 |
| kubernetes-api-from-ephemeral | curl K8s API | 403/401 | 200 |
| ms1-sa-to-vault | ms1 SA → vault:8200 | 403/timeout | 200 |
| ms1-sa-to-cerbos | ms1 SA → cerbos:3592 | 403/timeout | 200 |

**Controls tested:** AuthorizationPolicy workload boundaries, input validation.

---

## Category 06: Debug Endpoints

Tests Envoy admin port 15000 accessibility.

| Variant | From → To | SECURE | VULNERABLE |
|---------|-----------|--------|-----------|
| ms1-to-ms2-stats | ms1 → ms2:15000/stats | timeout/refused | 200 |
| ms1-to-ms2-config-dump | ms1 → ms2:15000/config_dump | timeout/refused | 200 |
| ms1-to-vault-admin | ms1 → vault:15000/config_dump | timeout/refused | 200 |
| external-admin-port | localhost:15000/stats | timeout/refused | 200 |
| ephemeral-to-gateway-admin | random pod → gateway:15000 | timeout/refused | 200 |

**Controls tested:** Envoy admin port binding, network policies.

---

## Category 07: RLS Variable Scope Leak

| Variant | SECURE | VULNERABLE |
|---------|--------|-----------|
| pii-no-context-zero-rows | 0 rows from employee_pii | > 0 rows |
| set-local-clears-on-commit | empty after COMMIT | value persists |
| session-scope-leak-demo | (informational) | — |
| ms2-pii-without-context | 0 rows | > 0 rows |
| employees-read-open | (informational) | — |
| bypassrls-not-granted | all app users = false | any = true |

**Controls tested:** PostgreSQL RLS policies, SET LOCAL scoping, role grants.

---

## Category 08: ExtAuthz Fail-Open

| Variant | SECURE | VULNERABLE |
|---------|--------|-----------|
| auth-down-denies-request | 403/503 | 200 |
| auth-down-public-still-works | 200 | blocked |
| auth-down-healthz-works | 200 | blocked |
| failopen-config-check | no failOpen:true | failOpen:true present |

**Controls tested:** ExtAuthz fail-close behavior, Istio extensionProvider config.

---

## Category 09: Cerbos Attribute Spoofing

| Variant | SECURE | VULNERABLE |
|---------|--------|-----------|
| unauthorized-sa-to-cerbos | 403 at network layer | Cerbos responds |
| spoofed-resource-attrs-denied | EFFECT_DENY | EFFECT_ALLOW |
| role-based-grant | (informational) confirms trust chain | — |
| resource-attr-from-db-not-http | 403 on spoofed view_sensitive | 200 |

**Controls tested:** AuthorizationPolicy on Cerbos, attribute trust boundary.

---

## Category 10: mTLS Enforcement

| Variant | SECURE | VULNERABLE |
|---------|--------|-----------|
| plaintext-rejected | connection reset/timeout | 200 |
| mTLS-approved-caller-works | 200 (positive check) | connection fails |
| svid-expiry-check | cert lifetime <= 24h | > 24h |
| peer-auth-strict-all-ns | all STRICT | any PERMISSIVE |
| default-ns-no-policy | (informational) | — |
| istioctl-tls-check | no CONFLICT | CONFLICT found |

**Controls tested:** PeerAuthentication STRICT mode, certificate lifecycle.

---

## Category 11: Static Analysis

| Variant | Tool | SECURE | VULNERABLE |
|---------|------|--------|-----------|
| shellcheck | Shell scripts | 0 errors | errors found |
| yamllint | Deployment YAMLs | 0 errors | errors found |
| bandit | Python code | 0 high severity | high severity found |
| checkov | K8s manifests | 0 failures | failures found |
| trivy | Filesystem scan | 0 HIGH/CRITICAL | findings |
| secrets-grep | Hardcoded secrets | none | matches found |
| vault-key-version | Key lifecycle | documented | — |

**Controls tested:** Code quality, known vulnerabilities, secrets hygiene.

---

## Category 12: Istio Configuration Audit

| Variant | Check | SECURE | VULNERABLE |
|---------|-------|--------|-----------|
| istioctl-analyze | Config analysis | 0 errors | errors |
| gateway-prestrip-present | EnvoyFilter exists | present | missing |
| request-auth-coverage | All services covered | 5/5 | missing |
| default-deny-check | No ALLOW-all policies | none | found |
| extauthz-path-coverage | ExtAuthz referenced | present | missing |
| peer-auth-audit | All STRICT | all | non-STRICT |
| envoyfilter-priority-order | Negative priority | < 0 | >= 0 |
| jwks-health | JWKS returns 200 | 200 | other |

**Controls tested:** Istio mesh configuration integrity, defense-in-depth completeness.

---

## Report Format

Reports are written to `security-tests/reports/attack-report-<timestamp>.md` with:
- Summary table of all categories
- Per-variant verdict (SECURE/VULNERABLE/ERROR)
- Evidence (response body) for VULNERABLE findings only
