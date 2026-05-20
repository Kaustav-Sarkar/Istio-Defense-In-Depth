# End-to-End Request Flows

This document traces complete request paths through the system, step by step. Each flow shows how the security layers compose to establish and propagate identity.

---

## 1. Browser Login Flow (OIDC Authorization Code)

A user with no existing session visits the application for the first time.

```mermaid
sequenceDiagram
    participant Browser
    participant Gateway as Istio Gateway
    participant AuthSvc as auth-service
    participant KC as Keycloak
    participant Vault
    participant DB as PostgreSQL (auth schema)

    Browser->>Gateway: GET https://app.localtest.me/auth/login
    Gateway->>AuthSvc: Route /auth/* (no ExtAuthz on this path)
    AuthSvc->>DB: create_oauth_state() → store SHA-256(state) with expiry
    AuthSvc-->>Browser: 302 Redirect → idp.localtest.me/realms/.../auth?state=...

    Browser->>Gateway: GET https://idp.localtest.me/realms/.../auth
    Gateway->>KC: Route idp.localtest.me (no ExtAuthz)
    KC-->>Browser: Login page (or SAML redirect if brokered)

    Browser->>KC: POST credentials
    KC-->>Browser: 302 Redirect → app.localtest.me/auth/callback?code=...&state=...

    Browser->>Gateway: GET /auth/callback?code=...&state=...
    Gateway->>AuthSvc: Route /auth/*

    AuthSvc->>DB: verify_oauth_state() → SELECT FOR UPDATE, mark consumed
    AuthSvc->>KC: POST /token (exchange authorization code)
    KC-->>AuthSvc: {access_token, id_token, refresh_token}

    AuthSvc->>AuthSvc: validate_bearer(access_token) → verify signature via JWKS
    AuthSvc->>AuthSvc: Extract sub, preferred_username, roles, groups, department

    AuthSvc->>DB: create_session() → INSERT into auth.sessions
    AuthSvc-->>Browser: 302 Redirect → / + Set-Cookie: zt_session={uuid}
```

### Step-by-step breakdown:

1. **Browser → `/auth/login`**: The gateway routes `/auth/*` directly to auth-service. No ExtAuthz — this avoids an authentication loop.

2. **State generation**: auth-service generates a `secrets.token_urlsafe(32)`, stores its SHA-256 hash in `auth.oauth_states` with a 15-minute expiry. The raw state goes in the redirect URL.

3. **Keycloak redirect**: Browser redirects to `idp.localtest.me`. Keycloak handles credential collection. If SAML brokering is configured, Keycloak further redirects to the enterprise IdP and normalizes the SAML assertion back into an OIDC session.

4. **Callback**: Browser returns to `/auth/callback` with an authorization code and the state parameter.

5. **State verification**: auth-service hashes the incoming state, does a `SELECT ... FOR UPDATE` to atomically check it hasn't been consumed and hasn't expired. Marks it consumed. This prevents CSRF and replay.

6. **Code exchange**: auth-service calls Keycloak's token endpoint (server-to-server, inside the mesh) with the authorization code + client_secret.

7. **Token validation**: auth-service validates the received access_token by fetching Keycloak's JWKS and verifying the RSA signature. Extracts user claims.

8. **Session creation**: A new row in `auth.sessions` stores: user_id (deterministic UUID5 from username), username, email, roles, groups, department, expiry (1 hour). The session ID is a random UUID4.

9. **Cookie set**: The response sets `zt_session={uuid}` as HttpOnly, Secure, SameSite=lax, path=/, max_age=3600.

---

## 2. Authenticated API Request (Profile Fetch)

An authenticated user requests `GET /api/profile/{employee_id}`.

```mermaid
sequenceDiagram
    participant Browser
    participant Gateway as Istio Gateway
    participant Lua as Pre-strip EnvoyFilter
    participant ExtAuthz as ExtAuthz Filter
    participant AuthSvc as auth-service
    participant Vault
    participant MS1Sidecar as MS1 Sidecar
    participant MS1 as ms1-profile-aggregator
    participant MS2Sidecar as MS2 Sidecar
    participant MS2 as ms2-employee-details
    participant Cerbos
    participant DB as PostgreSQL

    Browser->>Gateway: GET /api/profile/{id} + Cookie: zt_session=...
    Gateway->>Lua: Strip x-mesh-identity, x-ms*-user, x-ms*-role, x-platform-*
    Lua->>ExtAuthz: Forward cleaned request

    ExtAuthz->>AuthSvc: Check (cookie + path + method)
    AuthSvc->>DB: get_session(zt_session) → validate not expired/revoked
    AuthSvc->>AuthSvc: evaluate_request() → coarse policy: /api/profile/* allows [employee, manager, hr_admin]
    AuthSvc->>Vault: GET /v1/transit/keys/mesh-identity → latest key version
    AuthSvc->>AuthSvc: Build JWT payload (sub, roles, aud:[ms1,ms2,ms3], act, exp:+5min, jti)
    AuthSvc->>Vault: POST /v1/transit/sign/mesh-identity → sign(header.payload)
    Vault-->>AuthSvc: vault:v1:{base64_signature}
    AuthSvc->>AuthSvc: Assemble final JWT: header.payload.signature
    AuthSvc-->>ExtAuthz: 200 OK + x-mesh-identity: {jwt}

    ExtAuthz->>MS1Sidecar: Forward with x-mesh-identity header injected
    
    Note over MS1Sidecar: RequestAuthentication validates JWT (issuer, signature via JWKS)
    MS1Sidecar->>MS1Sidecar: Strip x-ms1-user, x-ms1-role
    MS1Sidecar->>MS1Sidecar: Project: x-ms1-user=claims.sub, x-ms1-role=claims.roles_csv
    MS1Sidecar->>MS1: Forward with x-ms1-user, x-ms1-role, x-mesh-identity (kept for forwarding)

    MS1->>MS2Sidecar: GET /api/employees/{id} + x-mesh-identity + x-request-id

    Note over MS2Sidecar: AuthorizationPolicy checks: source=ms1-sa, aud contains ms2, act.sub=ms1
    Note over MS2Sidecar: RequestAuthentication validates JWT
    MS2Sidecar->>MS2Sidecar: Strip x-ms2-user, x-ms2-role
    MS2Sidecar->>MS2Sidecar: Project: x-ms2-user=claims.sub, x-ms2-role=claims.roles_csv
    MS2Sidecar->>MS2: Forward with x-ms2-user, x-ms2-role

    MS2->>DB: SET LOCAL app.current_user_id, app.current_roles
    MS2->>DB: SELECT FROM hr.employees WHERE id = {id} (RLS enforced)
    DB-->>MS2: Row (if visible under RLS)
    MS2->>Cerbos: check_resources(principal, resource, action=view)
    Cerbos-->>MS2: {allowed: true, outputs: {visible_fields: [...]}}
    MS2->>MS2: apply_masking(row, visible_fields)
    MS2-->>MS1: Masked employee JSON

    MS1-->>Browser: Aggregated ProfileResponse
```

### Step-by-step breakdown:

**At the Gateway (steps 1-3):**

1. Request arrives with the `zt_session` cookie. The pre-strip Lua filter removes any externally-supplied identity headers (`x-mesh-identity`, `x-ms*-user/role`, `x-platform-*`).

2. The ExtAuthz policy matches `/api/*` paths and pauses the request, sending it to auth-service for evaluation.

**At auth-service / ExtAuthz (steps 4-9):**

3. auth-service extracts the session cookie, calls `get_session()` which validates the UUID, checks expiry, checks revocation, and updates `last_seen_at`.

4. `evaluate_request()` normalizes the path (strips `/verify` prefix if present), determines the coarse route/role policy. For `/api/profile/*`, allowed roles are: `employee`, `manager`, `hr_admin`.

5. If the user's roles intersect with allowed roles, auth-service builds the mesh token payload:
   - `sub`: deterministic UUID5 from username
   - `roles`: from session (array) + `roles_csv` (comma-separated for header projection)
   - `aud`: `["ms1-profile-aggregator", "ms2-employee-details", "ms3-hardware-assets"]`
   - `act`: `{"sub": "ms1-profile-aggregator"}` (delegation context)
   - `exp`: now + 5 minutes
   - `jti`: random UUID4
   - `kid`: latest Vault key version

6. Vault Transit signs the `header.payload` bytes and returns the signature in `vault:v1:{base64}` format. auth-service strips the prefix and assembles the final JWT.

7. Returns 200 with `x-mesh-identity` header. Istio's ExtAuthz mechanism injects this header into the upstream request.

**At MS1's sidecar (steps 10-12):**

8. The `RequestAuthentication` resource validates the JWT in `x-mesh-identity`:
   - Fetches JWKS from `http://auth-service.zt-apps.svc.cluster.local:8000/auth/jwks`
   - Verifies RS256 signature
   - Checks issuer = "auth-service"

9. The header-projection Lua filter strips any pre-existing `x-ms1-user`/`x-ms1-role`, then `outputClaimToHeaders` projects:
   - `x-ms1-user` ← `sub` claim
   - `x-ms1-role` ← `roles_csv` claim

10. MS1 receives both the projected legacy headers AND `x-mesh-identity` (forwardOriginalToken=true for ms1, since it needs to forward it downstream).

**At MS1 application (step 13):**

11. MS1 validates it has `x-ms1-user` and `x-ms1-role` headers (401 if missing). Extracts `x-mesh-identity` for downstream forwarding.

12. Fans out concurrent requests to MS2 (`/api/employees/{id}`, `/api/employees/{id}/financials`, `/api/employees/{id}/pii`) and MS3 (`/api/assets?employee_id={id}`), forwarding `x-mesh-identity` and `x-request-id`.

**At MS2's sidecar (steps 14-16):**

13. `AuthorizationPolicy` checks:
    - Source principal = `cluster.local/ns/zt-apps/sa/ms1-profile-aggregator-sa`
    - JWT claim `aud` contains `ms2-employee-details`
    - JWT claim `act.sub` = `ms1-profile-aggregator`

14. `RequestAuthentication` validates the JWT signature (same as ms1's sidecar).

15. Header projection: strips `x-ms2-user/role`, projects from verified claims. `forwardOriginalToken=false` — MS2 app never sees the raw JWT.

**At MS2 application (steps 17-21):**

16. MS2 extracts `x-ms2-user` (the subject) and `x-ms2-role` (comma-separated roles). Splits roles.

17. Sets RLS context: `SELECT set_config('app.current_user_id', ..., true)` and `set_config('app.current_roles', ..., true)` within the transaction.

18. Executes the query. PostgreSQL RLS evaluates the `employees_visibility` policy against the current config values.

19. Calls Cerbos with principal (user_id, roles) and resource (employee_id, manager_id, department, status) to get the authorization decision + visible fields output.

20. Applies field masking: only returns fields in the `visible_fields` set. Computes derived fields like `salary_band` if applicable.

21. Returns the masked JSON response.

---

## 3. Bearer Token API Request

An API client (curl, service account) uses a Keycloak access token directly.

```mermaid
sequenceDiagram
    participant Client as API Client (curl)
    participant Gateway as Istio Gateway
    participant AuthSvc as auth-service
    participant KC as Keycloak JWKS
    participant Vault

    Client->>Gateway: GET /api/holidays + Authorization: Bearer {keycloak_token}
    Gateway->>AuthSvc: ExtAuthz check

    AuthSvc->>AuthSvc: Extract "Bearer {token}" from Authorization header
    AuthSvc->>AuthSvc: jwt.get_unverified_header(token) → extract kid
    AuthSvc->>KC: GET /realms/.../protocol/openid-connect/certs
    KC-->>AuthSvc: JWKS {keys: [...]}
    AuthSvc->>AuthSvc: Find matching kid, reconstruct RSA public key
    AuthSvc->>AuthSvc: jwt.decode(token, pubkey, algorithms=[RS256], issuer, audience)
    AuthSvc->>AuthSvc: Extract sub, roles, email, groups, department

    Note over AuthSvc: Same flow as session-based from here
    AuthSvc->>Vault: Sign mesh token
    AuthSvc-->>Gateway: 200 + x-mesh-identity
    Gateway->>MS4: Forward to ms4-holiday-calendar (after sidecar projection)
```

### Key differences from browser flow:

- No session lookup — auth-service checks the `Authorization` header first, before falling back to cookie.
- Token validation happens against Keycloak's JWKS endpoint (fetched per request — see audit note on caching).
- The audience validation has a fallback: if `aud` doesn't match, checks `azp` claim. This handles Keycloak's behavior where some token types use `azp` instead of `aud`.
- User identity is derived the same way: UUID5 from `preferred_username`, or raw `sub` if no username.

---

## 4. Service-to-Service Call with Delegation (MS1 → MS2)

This details what happens at the network level when MS1 calls MS2 internally.

```mermaid
sequenceDiagram
    participant MS1Pod as MS1 Pod (app container)
    participant MS1Proxy as MS1 Envoy Sidecar (outbound)
    participant MS2Proxy as MS2 Envoy Sidecar (inbound)
    participant MS2Pod as MS2 Pod (app container)

    MS1Pod->>MS1Proxy: HTTP GET ms2-employee-details:8000/api/employees/{id}<br/>Headers: x-mesh-identity, x-request-id
    
    Note over MS1Proxy,MS2Proxy: Istio mTLS: MS1's sidecar presents<br/>SPIFFE cert: spiffe://cluster.local/ns/zt-apps/sa/ms1-profile-aggregator-sa

    MS1Proxy->>MS2Proxy: mTLS connection established

    Note over MS2Proxy: AuthorizationPolicy evaluation:<br/>1. source.principal == ms1-profile-aggregator-sa ✓<br/>2. request.auth.claims[aud] contains "ms2-employee-details" ✓<br/>3. request.auth.claims[act][sub] == "ms1-profile-aggregator" ✓

    Note over MS2Proxy: RequestAuthentication:<br/>1. Extract JWT from x-mesh-identity header<br/>2. Fetch JWKS from auth-service<br/>3. Verify RS256 signature ✓<br/>4. Check issuer == "auth-service" ✓

    MS2Proxy->>MS2Proxy: Lua filter: remove x-ms2-user, x-ms2-role
    MS2Proxy->>MS2Proxy: outputClaimToHeaders: x-ms2-user=sub, x-ms2-role=roles_csv
    MS2Proxy->>MS2Pod: Forward with projected headers only (no x-mesh-identity)
```

### Trust checks at MS2's boundary (all must pass):

| Check | Layer | What it proves |
|-------|-------|----------------|
| mTLS source principal | Istio AuthorizationPolicy | The calling *workload* is MS1 (not a rogue pod) |
| JWT signature valid | RequestAuthentication | The token was minted by auth-service (Vault-signed) |
| `aud` contains `ms2-employee-details` | AuthorizationPolicy `when` | The token was intended for this service |
| `act.sub` = `ms1-profile-aggregator` | AuthorizationPolicy `when` | The delegation context is legitimate |
| Token not expired | RequestAuthentication | The token is fresh (5 min window) |

A stolen token replayed from a different pod fails check #1. A token minted for a different service fails check #3. An old token fails check #5.

---

## 5. Denied Request Flow

When authorization fails at any layer.

```mermaid
flowchart TD
    Request[Incoming Request]
    
    Request --> PreStrip[Gateway Pre-strip]
    PreStrip --> ExtAuthz{ExtAuthz Check}
    
    ExtAuthz -->|No valid session/bearer| Deny401[401 Unauthorized<br/>No mesh token minted]
    ExtAuthz -->|Wrong role for route| Deny401
    ExtAuthz -->|Valid| MeshToken[Mesh token injected]
    
    MeshToken --> SidecarJWT{Sidecar JWT Validation}
    SidecarJWT -->|Invalid signature| Deny403A[403 Forbidden<br/>Istio rejects at sidecar]
    SidecarJWT -->|Expired| Deny403A
    SidecarJWT -->|Wrong issuer| Deny403A
    
    SidecarJWT -->|Valid| AuthzPolicy{AuthorizationPolicy}
    AuthzPolicy -->|Wrong source principal| Deny403B[403 RBAC: access denied]
    AuthzPolicy -->|Wrong aud/act claims| Deny403B
    
    AuthzPolicy -->|Pass| AppLayer[Application receives request]
    AppLayer --> MissingHeaders{Required headers present?}
    MissingHeaders -->|No x-msN-user/role| Deny401App[401 Missing headers]
    
    MissingHeaders -->|Yes| CerbosCheck{Cerbos check}
    CerbosCheck -->|Denied| Deny403C[403 Forbidden by Cerbos]
    CerbosCheck -->|Cerbos unreachable| Deny403C
    
    CerbosCheck -->|Allowed| RLS[PostgreSQL query with RLS]
    RLS -->|Row not visible| EmptyResult[Empty result / 404]
    RLS -->|Visible| Masked[Apply field masking → Response]
```

### Fail-closed guarantees:

| Component Down | Effect |
|----------------|--------|
| auth-service | ExtAuthz can't evaluate → deny (503/401) |
| Vault | Can't sign mesh token → deny (500 at auth-service) |
| Keycloak JWKS | Can't validate bearer → deny. Sidecars use cache until TTL. |
| Cerbos | `check_cerbos()` catches exception → returns `{allowed: False}` → 403 |
| PostgreSQL | No session validation, no data → total failure |

---

## 6. Logout Flow

```mermaid
sequenceDiagram
    participant Browser
    participant Gateway as Istio Gateway
    participant AuthSvc as auth-service
    participant KC as Keycloak
    participant DB as PostgreSQL

    Browser->>Gateway: GET /auth/logout + Cookie: zt_session=...
    Gateway->>AuthSvc: Route /auth/* (no ExtAuthz)
    AuthSvc->>DB: revoke_session(zt_session) → SET revoked=true
    AuthSvc-->>Browser: 302 Redirect → Keycloak logout endpoint<br/>+ Delete-Cookie: zt_session
    Browser->>KC: GET /logout?post_logout_redirect_uri=/
    KC-->>Browser: 302 → /
```

Post-logout state:
- The `zt_session` cookie is deleted from the browser.
- The session row in PostgreSQL has `revoked=true` — any subsequent use of the old session ID will be rejected by `get_session()`.
- Keycloak's own session is also terminated, so re-login requires full authentication.

---

## 7. Vault Key Rotation Flow

When the Vault Transit signing key is rotated:

```mermaid
sequenceDiagram
    participant Operator
    participant Vault
    participant AuthSvc as auth-service
    participant Sidecars as Service Sidecars

    Operator->>Vault: POST /v1/transit/keys/mesh-identity/rotate
    Note over Vault: New key version created (e.g., v2)<br/>Old version (v1) still available for verification

    Note over AuthSvc: Next request: get_latest_key_version() returns "2"
    AuthSvc->>Vault: Sign with key version 2
    AuthSvc->>AuthSvc: Mint token with kid="2"

    Note over Sidecars: JWKS cache still has only v1 public key
    Sidecars->>AuthSvc: GET /auth/jwks (on cache refresh)
    AuthSvc->>Vault: GET /v1/transit/keys/mesh-identity
    Vault-->>AuthSvc: {keys: {1: {public_key: ...}, 2: {public_key: ...}}}
    AuthSvc-->>Sidecars: JWKS with both kid=1 and kid=2

    Note over Sidecars: Now can verify tokens signed by either version
    Note over Sidecars: After 5 min, all v1 tokens have expired naturally
```

### Rotation window:
- Old tokens (kid=1) remain valid until their 5-minute expiry.
- New tokens immediately use kid=2.
- The JWKS endpoint always serves ALL active key versions.
- Brief window: if a sidecar's JWKS cache hasn't refreshed but receives a kid=2 token, that token will be rejected until the cache refreshes. Istio's default JWKS refresh interval (typically 5 minutes) means this window is short.
