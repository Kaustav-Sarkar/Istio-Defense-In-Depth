import json
import base64
import uuid
from datetime import datetime, timedelta, timezone
import vault_client

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def create_mesh_token(decision: dict) -> str:
    """Creates a JWT signed by Vault Transit"""
    
    key_version = vault_client.get_latest_key_version()
    
    # 1. Create Header
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": str(key_version)
    }
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    header_b64 = base64url_encode(header_json)
    
    # 2. Create Payload
    now = datetime.now(timezone.utc)
    from config import settings
    exp = now + timedelta(minutes=settings.MESH_TOKEN_EXPIRY_MINUTES) # Short lived mesh assertion
    
    payload = {
        "iss": "auth-service",
        "sub": decision.get("subject"),
        "preferred_username": decision.get("username"),
        "email": decision.get("email"),
        "roles": decision.get("roles", []),
        "roles_csv": ",".join(decision.get("roles", [])),
        "groups": decision.get("groups", []),
        "department": decision.get("department"),
        "aud": decision.get("audience", []),
        "azp": "auth-service",
        "act": decision.get("act") or (
            {"sub": "ms1-profile-aggregator"}
            if "ms1-profile-aggregator" in decision.get("audience", [])
            else None
        ),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
        "request_id": decision.get("request_id")
    }
    
    # Exclude None values
    payload = {k: v for k, v in payload.items() if v is not None}
    
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64url_encode(payload_json)
    
    # 3. Sign using Vault
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature_b64 = vault_client.sign_payload(signing_input)
    
    # Convert standard base64 to base64url
    sig_bytes = base64.b64decode(signature_b64)
    sig_b64url = base64url_encode(sig_bytes)
    
    # 4. Assemble Token
    return f"{header_b64}.{payload_b64}.{sig_b64url}"
