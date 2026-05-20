# Security Architecture — Design Rationale

This document captures the security reasoning behind every layer of the zero-trust stack: why each component exists, what specific attack it prevents, and what would break if it were removed. It assumes familiarity with the codebase. It is not a setup guide.

---

## Design Philosophy

The threat model assumes a hostile interior. Any service, pod, or process inside the cluster is a potential attacker — whether through direct compromise, misconfiguration, or supply-chain. No request is trusted because of where it comes from. Trust is established cryptographically at every boundary, from the external browser down to the Postgres row.

Each layer has an independent failure mode. The goal is not redundancy but that subverting the system requires defeating all layers simultaneously, which requires compromising multiple independent components (Keycloak, Vault, Istiod, Postgres).

---

## Part 1: External Authentication

### Why Keycloak / OIDC Instead of Custom Auth

Credential handling is a liability. Every custom password login endpoint is a potential target for brute force, credential stuffing, and timing attacks. Keycloak externalises this entirely: it owns the credential store, the login UI, the hashed passwords (bcrypt/pbkdf2), and MFA. The application never touches a raw password.

OIDC (OpenID Connect) is the protocol that lets the application delegate authentication to Keycloak without receiving credentials. The application only ever receives a cryptographically signed token asserting identity.

### The Authorization Code Flow — Why Two Steps

The naive approach would be for Keycloak to redirect the browser back to the app with a token in the URL:

```
https://app.localtest.me/callback?access_token=eyJhbGci...
```

This is the deprecated **Implicit Flow**. Tokens in URLs appear in browser history, server access logs, and `Referer` headers sent to every third-party resource on the page (analytics, CDN, fonts). A 5-minute token in a URL is a 5-minute credential sitting in plaintext in log files.

The Authorization Code Flow solves this with a two-step process:

**Step 1 — Keycloak sends a code, not a token:**
```
https://app.localtest.me/auth/callback?code=SplxlOBeZQQYbYS6WxSbIA
```
The code is a short-lived (≈60s), single-use, opaque string. Useless alone.

**Step 2 — auth-service exchanges code for token in a server-to-server call:**
```python
# oidc.py:23-36
data = {
    "grant_type": "authorization_code",
    "client_id": settings.KEYCLOAK_CLIENT_ID,
    "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
    "code": code,
    "redirect_uri": redirect_uri,
}
response = _client.post(token_url, data=data)
```

The `client_secret` never touches the browser. The real token is fetched in a direct HTTPS call between auth-service and Keycloak — it never appears in any URL. The code alone is worthless without the secret.

**Why the browser must be in the loop at all:**

The browser is the only channel through which a session cookie can be delivered. HTTP cookies are set via `Set-Cookie` on a response to a browser request. There is no push mechanism. The callback redirect is that request — it's the browser saying "I completed authentication" and auth-service responding with `Set-Cookie`. Without the browser carrying the code back, auth-service has no request to respond to and no way to identify which of potentially thousands of concurrent login sessions to attach the cookie to.

### The State Parameter — CSRF on the OAuth Callback

**Attack (OAuth Login CSRF, RFC 6749 §10.12):**

1. Attacker authenticates at Keycloak, gets a callback URL: `/auth/callback?code=ATTACKER_CODE`
2. Attacker does not follow the redirect — saves it
3. Attacker embeds the URL in evil.com: `<img src="https://app.localtest.me/auth/callback?code=ATTACKER_CODE">`
4. Victim visits evil.com — browser loads the URL
5. auth-service exchanges `ATTACKER_CODE`, creates a session, sets a cookie on the **victim's browser**
6. Victim is now logged in as the attacker

This is "Login CSRF" — forcing a user to authenticate as someone else. The victim then enters data into the application, which is associated with the attacker's identity. The attacker logs in and retrieves it.

**The fix — state token:**
```python
# sessions.py:8-20
def create_oauth_state(db, expires_in_minutes=15):
    state = secrets.token_urlsafe(32)          # 256 bits, unpredictable
    state_hash = hashlib.sha256(state.encode()).hexdigest()
    db.add(OAuthState(state_hash=state_hash, expires_at=...))
    return state
```

The state is a one-time-use, 15-minute-expiry token stored in Postgres. Keycloak echoes it back in the callback URL. auth-service verifies it exists and hasn't been consumed before proceeding:

```python
# sessions.py:22-37
oauth_state.consumed_at = datetime.now(timezone.utc)  # mark used — can never be reused
```

The attack fails because even if the attacker crafts a valid `(code, state)` pair, the state is consumed on first use. The victim's browser can't replay it.

### Session Management — Opaque Sessions Over JWTs in Cookies

After validating the Keycloak access token, auth-service creates an opaque session row in Postgres rather than issuing a JWT cookie:

```python
# main.py:73-93
session = sessions.create_session(db, user_id=user_id, roles=roles, ...)
response.set_cookie(key=settings.COOKIE_NAME, value=str(session.id),
    httponly=True, secure=True, samesite="lax")
```

**Why opaque sessions, not JWTs in cookies:**

JWTs have a fixed expiry baked into the token. A JWT in a cookie cannot be revoked before it expires — if a user logs out or is compromised, their token is still valid until `exp`. Opaque sessions have a `revoked` flag:

```python
# sessions.py:79-90
def revoke_session(db, session_id):
    session.revoked = True
    db.commit()
```

Setting `revoked=True` kills the session immediately on the next request. This is server-side control over authentication state that JWTs cannot provide.

**Cookie flags:**
- `HttpOnly` — JavaScript cannot read `document.cookie`. XSS cannot exfiltrate the session ID.
- `Secure` — cookie only transmitted over HTTPS. Network sniffing cannot capture it.
- `SameSite=Lax` — browser does not send cookie on cross-site requests. CSRF attacks using the session cookie are blocked at the browser level.

### JWT Signature Validation — How auth-service Trusts Keycloak Tokens

Keycloak signs JWTs with an RSA private key. auth-service has no pre-shared secret with Keycloak. It trusts tokens by verifying the signature against Keycloak's public key, fetched from the JWKS endpoint:

```python
# oidc.py:38-42
def _get_keycloak_public_keys():
    jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    return _client.get(jwks_url).json().get("keys", [])
```

The JWKS endpoint is public — it only contains public keys. No key exchange, no pre-configuration. The `kid` field in the JWT header identifies which key version signed the token:

```python
# oidc.py:68-103
unverified_header = jwt.get_unverified_header(token)
kid = unverified_header.get("kid")
public_key = get_public_key(kid)   # finds matching key from JWKS
decoded = jwt.decode(token, public_key, algorithms=["RS256"], ...)
```

This is the same mechanism Envoy sidecars use to verify mesh tokens — the pattern is consistent at every layer.

---

## Part 2: The Gateway Boundary

Every inbound request to `/api/*` passes through three sequential operations at the Istio Ingress Gateway before any backend service sees it.

### Operation 1 — Header Stripping (gateway-prestrip EnvoyFilter)

```lua
-- envoyfilter-gateway-prestrip.yaml, runs at priority -100 (before everything)
function envoy_on_request(request_handle)
  local headers_to_remove = {}
  for key, value in pairs(request_handle:headers()) do
    local lower_key = string.lower(key)
    if string.match(lower_key, "^x%-platform%-") or
       lower_key == "x-mesh-identity" or
       string.match(lower_key, "^x%-ms%d%-user") or
       string.match(lower_key, "^x%-ms%d%-role") then
      table.insert(headers_to_remove, lower_key)
    end
  end
  for _, key in ipairs(headers_to_remove) do
    request_handle:headers():remove(key)
  end
end
```

**Attack (Header Injection):** The entire internal identity system rests on the invariant that `x-ms2-user` was written by Envoy from a verified JWT — never by the client. Without stripping, an attacker sends:

```
GET /api/profile/alice
x-ms2-user: henry.hradmin
x-ms2-role: hr_admin,employee
```

If ms2 trusts these headers directly, the attacker has hr_admin access with zero cryptography. This is not theoretical — it has been exploited in production microservices architectures.

The strip runs at priority `-100`, meaning it executes before ExtAuthz and before any other filter. Whatever the external client sends, those headers are gone before anything processes them.

### Operation 2 — ExtAuthz (auth-service /verify)

The `gateway-extauthz` AuthorizationPolicy routes all `/api/*` requests to auth-service before forwarding:

```yaml
# authz-gateway-extauthz.yaml
action: CUSTOM
provider: auth-service-extauthz
rules:
  - to:
      operation:
        paths: ["/api/*"]
        notPaths: ["/api/offices", "/api/offices/*"]   # public GET allowed
```

What auth-service does during `/verify`:

1. **Checks bearer token or session cookie** — validates one of the two credential types
2. **Coarse route/role policy** — `employee` can reach `/api/profile`, only `public_data_admin` can write to `/api/offices`
3. **On ALLOW: mints a mesh token** — calls Vault Transit to sign an `x-mesh-identity` JWT encoding the verified identity

The Istio mesh config specifies exactly what headers go to auth-service and what comes back:

```yaml
# istio-profile.yaml
includeRequestHeadersInCheck: ["cookie", "authorization", "x-request-id"]
headersToUpstreamOnAllow: ["x-mesh-identity"]
```

`x-mesh-identity` is only injected into the upstream request if auth-service returns HTTP 200. A 401 response kills the request at the gateway — no backend service handles unauthenticated requests.

### Operation 3 — Vault Transit (Signing Without Holding the Key)

auth-service needs to sign the mesh token. The question is where the private key lives.

**If auth-service holds the key directly:**
```python
private_key = os.environ["MESH_SIGNING_KEY"]
signed_token = jwt.encode(payload, private_key, algorithm="RS256")
```

The key is in memory, in environment variables, in the Kubernetes Secret backing it. A compromised auth-service (SSRF, info disclosure, RCE) gives the attacker the key. With the key they mint valid `x-mesh-identity` tokens for any user with any roles — offline, forever, without going through auth-service.

**With Vault Transit:**
```python
# vault_client.py:7-31
def sign_payload(payload_bytes: bytes) -> str:
    response = _client.post(
        f"{VAULT_URL}/v1/transit/sign/mesh-identity",
        headers={"X-Vault-Token": settings.VAULT_TOKEN},
        json={"input": base64.b64encode(payload_bytes).decode()}
    )
    sig = response.json()["data"]["signature"]   # "vault:v1:<base64sig>"
    return sig.split(":")[2]                      # only the signature, never the key
```

auth-service sends Vault the data-to-sign. Vault returns only the signature. The private key is generated and stored inside Vault's encrypted storage and has no export operation by design. auth-service never holds it, never sees it.

To forge tokens, an attacker needs auth-service's Vault token AND unrestricted Vault API access AND for access to not be revoked. Every signing call is logged in Vault's audit log. The `allow-auth-to-vault` AuthorizationPolicy limits Vault access to only `auth-service-sa` — even a compromised ms1 or ms2 cannot call Vault.

**The mesh token payload:**
```python
# mesh_tokens.py:28-49
payload = {
    "iss": "auth-service",
    "sub": decision["subject"],            # stable user UUID
    "roles": decision["roles"],
    "roles_csv": ",".join(roles),
    "aud": decision["audience"],           # ["ms1-profile-aggregator", "ms2-employee-details", ...]
    "act": {"sub": "ms1-profile-aggregator"},  # which service is acting
    "exp": now + timedelta(minutes=MESH_TOKEN_EXPIRY_MINUTES),
    "kid": str(vault_client.get_latest_key_version())
}
```

`aud` specifies which services the token is valid for. A token minted for `/api/holidays` has `aud: ["ms4-holiday-calendar"]` and cannot be presented to ms2. `act.sub` records ms1 as the acting party — ms2 cannot be reached except via ms1.

### Key Rotation

Vault's Transit engine versions keys. A complete rotation has two steps:

```bash
./scripts/rotate-vault-key.sh    # rotate key + bump min_decryption_version
```

This creates a new key pair (e.g. v2) and sets `min_decryption_version=2`, removing v1 from the API. New tokens are signed with v2 (`kid: "2"`). In-flight tokens carrying `kid: "1"` expire within 5 minutes (token TTL). Istio sidecars refresh JWKS within 20 minutes (cache TTL). Zero downtime, zero coordination required.

The `--grace` flag waits 5 minutes before invalidating old keys, allowing in-flight tokens to expire naturally.

auth-service's `/auth/jwks` endpoint translates Vault's key format to standard JWKS, returning only keys at or above `min_decryption_version`:

```python
# jwks.py:12-37
def get_jwks():
    keys = vault_client.get_public_keys()    # {1: {public_key: "PEM..."}, 2: {...}}
    for version, key_info in keys.items():
        jwks["keys"].append({
            "kty": "RSA",
            "kid": str(version),             # Envoy uses kid to pick the right key
            "n": ..., "e": ...
        })
    return jwks
```

Vault does not expose a JWKS endpoint — that translation is auth-service's job.

---

## Part 3: Intra-Cluster Security

After the gateway, auth-service is no longer in the critical path. Each service-to-service hop is secured by the Envoy sidecar — no central authority involved.

### mTLS — Cryptographic Service Identity

`PeerAuthentication STRICT` across all four namespaces (`zt-apps`, `zt-data`, `zt-security`, `zt-identity`) means every TCP connection between services requires mutual TLS. Both sides present certificates. Plaintext is rejected at the sidecar before a single byte reaches the application.

Certificates are SPIFFE SVIDs provisioned automatically by Istiod:
```
spiffe://cluster.local/ns/zt-apps/sa/ms1-profile-aggregator-sa
```

The identity is bound to the Kubernetes service account — the application cannot influence it. Forgery requires compromising Istiod or the cluster CA.

**Attack prevented (Lateral Movement, MITRE ATT&CK T1021):** Without mTLS, any pod inside the cluster can send requests to any other pod. A compromised batch job in `zt-apps` can hit ms2 directly. With mTLS STRICT, a pod without a valid cert cannot establish a connection. Period.

### AuthorizationPolicies — Network Least Privilege

mTLS proves identity. AuthorizationPolicies decide whether that identity is permitted.

```yaml
# authz-workload-boundaries.yaml — selected excerpts

# ms2 only accepts from ms1
allow-ms1-to-ms2:
  selector: app: ms2-employee-details
  from:
    principals: [cluster.local/ns/zt-apps/sa/ms1-profile-aggregator-sa]

# Vault only accepts from auth-service
allow-auth-to-vault:
  selector: app: vault
  from:
    principals: [cluster.local/ns/zt-apps/sa/auth-service-sa]

# Postgres only from explicitly listed service accounts
allow-approved-postgres-clients:
  selector: app: postgres
  from:
    principals: [auth-service-sa, ms2-employee-details-sa, ms3-hardware-assets-sa, ...]
```

Default is deny-all. A service not listed cannot reach the target regardless of valid mTLS cert.

**Attack prevented (Blast Radius Containment):** A compromised ms4 (holiday calendar) can only reach what its service account permits — `public_data` Postgres schema and Cerbos. It cannot pivot to ms2 employee data, cannot reach Vault, cannot call auth-service's full API. The compromise is structurally bounded.

### JWT Claim Checks in AuthorizationPolicy

AuthorizationPolicies go beyond source identity. They also enforce claims inside the mesh token:

```yaml
# authz-workload-boundaries.yaml
allow-ms1-to-ms2:
  when:
    - key: request.auth.claims[aud]
      values: ["ms2-employee-details"]     # token must be addressed to ms2
    - key: request.auth.claims[act][sub]
      values: ["ms1-profile-aggregator"]   # ms1 must be the acting party
```

**Attack prevented (Token Replay / Confused Deputy):** Even with a valid mTLS cert from ms1-sa, a request is rejected if the JWT was minted for a different audience. A token for `/api/holidays` (aud: ms4) cannot be replayed against ms2. The `act.sub` check ensures ms2 is only callable through ms1 — not directly, not from a compromised ms4 that somehow obtained a token.

### Header Stripping at Sidecar (Defense in Depth)

Each service sidecar also strips its own identity headers before the JWT validation filter runs:

```lua
-- header-projection-ms2.yaml (Lua EnvoyFilter on ms2's inbound sidecar)
function envoy_on_request(request_handle)
  request_handle:headers():remove("x-ms2-user")
  request_handle:headers():remove("x-ms2-role")
  -- JWT validation runs after this, projecting fresh values from the verified token
end
```

Even if a request arrives from inside the cluster with spoofed `x-ms2-user` headers, they are stripped before the JWT projection overwrites them with verified values. The gateway strip handles external requests; the sidecar strip handles internal ones.

### RequestAuthentication — JWT Verification + Claim Projection

Configured for every service via `jwks-cache-policy.yaml`:

```yaml
jwtRules:
  - issuer: "auth-service"
    jwksUri: "http://auth-service.zt-apps.svc.cluster.local:8000/auth/jwks"
    fromHeaders:
      - name: "x-mesh-identity"
    outputClaimToHeaders:
      - header: "x-ms2-user"
        claim: "sub"
      - header: "x-ms2-role"
        claim: "roles_csv"
```

Istiod fetches the JWKS from auth-service and pushes the key material to all Envoy sidecars. Sidecars cache it. On each inbound request, the sidecar verifies the `x-mesh-identity` JWT and projects verified claims as plain headers. ms2 reads `x-ms2-user` knowing it came from a cryptographically verified token — the application itself does not handle JWT validation.

---

## Part 4: Application-Level Authorization (Cerbos)

By the time a request reaches ms2's application code, Istio has established: the caller is ms1 (mTLS), the mesh token is valid and audience-correct, and the projected headers are trustworthy. But none of this addresses *resource-level* questions:

- Can alice view bob's salary?
- Can mary (manager) see salary details for her direct reports?
- Can henry (hr_admin) update anyone's record?

These depend on runtime resource attributes — who owns the record, who manages the employee. ExtAuthz at the gateway has no access to this context.

Cerbos is a policy evaluation engine. ms2 calls it per request with the full context:

```python
# cerbos_client.py:8-56
payload = {
    "principal": {
        "id": "alice-uuid",
        "roles": ["employee"]
    },
    "resources": [{
        "actions": ["view_sensitive"],
        "resource": {
            "kind": "employee_profile",
            "id": "bob-uuid",
            "attr": {
                "id": "bob-uuid",
                "manager_id": "alice-uuid"   # is alice bob's manager?
            }
        }
    }]
}
```

The policy (`cerbos/policies/employee_profile.yaml`) encodes the business rules:

```yaml
# A manager can view_sensitive for their direct report only
- actions: ["view_sensitive"]
  effect: EFFECT_ALLOW
  roles: ["manager"]
  condition:
    match:
      expr: request.principal.id == request.resource.attr.manager_id
  output:
    expr: '{"visible_fields": ["name", "title", "department", "salary_band"]}'

# An employee can view_sensitive their own record only
- actions: ["view_sensitive"]
  effect: EFFECT_ALLOW
  roles: ["employee"]
  condition:
    match:
      expr: request.principal.id == request.resource.attr.id
  output:
    expr: '{"visible_fields": ["name", "title", "department", "salary_band", "base_salary", "ssn"]}'
```

Cerbos returns `allowed: true/false` and `visible_fields` — the list of columns the caller is permitted to see. ms2 fetches the full row from Postgres and applies field masking based on this output. The response contains only permitted fields.

Cerbos fails closed:
```python
# cerbos_client.py:57-60
except Exception as e:
    return {"allowed": False, "outputs": {}}
```

If Cerbos is unreachable or returns an error, access is denied.

**Why not encode these rules in ms2's code?** Authorization conditions embedded in service code scatter across dozens of endpoints, have no unified audit trail, and require a code deploy to change. Cerbos policies are a Kubernetes ConfigMap — a policy change is a ConfigMap update with no service restart.

---

## Part 5: Database Security

### Schema Segregation and Postgres Roles

Each service has its own Postgres role with access to only its schema:

```sql
-- migrations/003_runtime_roles.sql
GRANT USAGE ON SCHEMA hr TO ms2_hr_role;          -- ms2 only
GRANT USAGE ON SCHEMA it TO ms3_it_role;           -- ms3 only
GRANT USAGE ON SCHEMA public_data TO ms4_public_readwrite_role;
GRANT USAGE ON SCHEMA auth TO auth_service_role;

GRANT SELECT, INSERT, UPDATE, DELETE ON hr.employees TO ms2_hr_role;
-- ms3 cannot query hr.employees (only has REFERENCES for FK constraints)
```

ms4 connecting to Postgres cannot execute any query against `hr.*` — the role doesn't have `USAGE` on the schema, let alone table permissions. This is enforced by Postgres, not by application code.

### Row Level Security — The Database Safety Net

RLS is not per-user rules. It is generic policies that evaluate at query time using transaction-local runtime variables. ms2 sets these at the start of every transaction:

```python
# rls.py:7-19
await session.execute(
    text("SELECT set_config('app.current_user_id', :user_id, true)"),
    {"user_id": user_id}
)
await session.execute(
    text("SELECT set_config('app.current_roles', :roles, true)"),
    {"roles": roles}
)
```

`true` = transaction-local. Variables vanish on commit/rollback. If a transaction reaches Postgres without setting context, `current_setting` returns empty/null and policies that depend on it deny access.

**`hr.employees` (non-sensitive: name, title, department)**
```sql
CREATE POLICY employees_visibility ON hr.employees
  USING (
    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');
```
SELECT: any authenticated principal (non-empty `app.current_user_id`) can read all directory rows; Cerbos masks returned fields. WRITE: hr_admin only. Missing RLS context returns zero rows.

**`hr.employee_pii` (sensitive: SSN, DOB, home address)**
```sql
CREATE POLICY employee_pii_visibility ON hr.employee_pii
  USING (
    current_setting('app.current_roles', true) LIKE '%hr_admin%'
    OR employee_id::text = current_setting('app.current_user_id', true)
    OR EXISTS (
      SELECT 1 FROM hr.employees e
      WHERE e.id = employee_id
        AND e.manager_id::text = current_setting('app.current_user_id', true)
    )
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%hr_admin%');
```

Three SELECT conditions: hr_admin sees all rows; `employee_id = current_user_id` lets an employee see their own PII; the EXISTS subquery lets a manager see their direct report's PII by joining `hr.employees` to check `manager_id`. The subquery is evaluated live per-row — manager changes take effect immediately without any cache.

**`hr.employee_financials` (sensitive: base salary, bonus, bank account)**

Identical structure to `employee_pii`. Note: RLS allows the manager to see the full financial row. Cerbos further restricts the returned fields — managers see `salary_band` but not `base_salary`. RLS controls which *rows*, Cerbos controls which *columns*.

**`it.hardware_assets` (device, MAC, serial number)**
```sql
CREATE POLICY hardware_assets_visibility ON it.hardware_assets
  USING (
    current_setting('app.current_roles', true) LIKE '%it_admin%'
    OR employee_id::text = current_setting('app.current_user_id', true)
  )
  WITH CHECK (current_setting('app.current_roles', true) LIKE '%it_admin%');
```

it_admin sees all assets. An employee sees only their assigned hardware. No manager check — hardware visibility is IT's domain, not management's.

`FORCE ROW LEVEL SECURITY` on all four tables means the policy applies even to the table owner. There is no SQL syntax that bypasses an RLS policy without superuser privileges.

**Why both Cerbos AND RLS for similar rules?**

They have independent failure modes and different granularities:
- Cerbos is application-layer. A bug in ms2 that skips `check_cerbos` still hits Postgres. Postgres enforces regardless.
- RLS is inside the database engine. ms2 cannot write a query that bypasses it — Postgres rewrites every query to include the policy predicate before execution.
- Cerbos controls field visibility. RLS controls row access. They operate on different axes.

---

## Threat Model Summary

| Attack | Layer(s) that prevent it |
|--------|--------------------------|
| Token leakage via browser history / server logs | Authorization Code Flow — token never in URL |
| Stolen authorization code used without server | `client_secret` required to exchange code |
| OAuth Login CSRF — victim forced into attacker's session | State parameter (one-time, 16-minute expiry) |
| Session cookie theft via XSS | `HttpOnly` flag — JS cannot read cookie |
| Session cookie theft via network sniffing | `Secure` flag + HTTPS enforced at gateway |
| CSRF abuse of session cookie from cross-site page | `SameSite=Lax` — browser blocks cross-site requests |
| Session that cannot be killed server-side | Opaque sessions with `revoked` flag in Postgres |
| Header injection — attacker sends trusted internal headers | `gateway-prestrip` EnvoyFilter strips all trusted headers at entry |
| Header injection from internal services | Per-sidecar EnvoyFilter strips headers before JWT projection |
| Unauthenticated access to API endpoints | ExtAuthz — auth-service must approve before gateway forwards |
| Compromised auth-service → private key exfiltration | Vault Transit — key never leaves Vault, only signatures returned |
| Token replay against wrong service | `aud` claim check in AuthorizationPolicy |
| Confused deputy — service calling beyond its scope | `act.sub` claim check; AuthorizationPolicy limits source principals |
| Lateral movement after pod compromise | mTLS STRICT + AuthorizationPolicies — attacker bounded by service account permissions |
| Compromised pod pivoting to Vault | `allow-auth-to-vault` limits Vault access to auth-service-sa only |
| Forged service identity at network level | mTLS with SPIFFE SVIDs — requires compromising Istiod or cluster CA |
| Bypassing Cerbos via code bug | Postgres RLS enforces same rules at DB level |
| SQL query returning rows beyond access scope | RLS policies with transaction-local context — enforced by Postgres engine |
| Manager-change not reflected in access control | RLS manager check is a live subquery — no cache |
| One service reading another service's DB schema | Postgres role-per-service with schema-level grants |
| Key compromise — old tokens valid forever | Vault versioned keys — rotate without breaking existing tokens, old versions kept for 5-min expiry window |
