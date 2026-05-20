import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from config import settings
import base64
import urllib.parse

_client = httpx.Client(timeout=settings.OIDC_HTTP_TIMEOUT_SECONDS)

def get_login_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state
    }
    query = urllib.parse.urlencode(params)
    return f"{settings.KEYCLOAK_PUBLIC_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/auth?{query}"

def exchange_code(code: str, redirect_uri: str) -> dict:
    token_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    
    data = {
        "grant_type": "authorization_code",
        "client_id": settings.KEYCLOAK_CLIENT_ID,
        "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    
    response = _client.post(token_url, data=data)
    response.raise_for_status()
    return response.json()

def _get_keycloak_public_keys() -> list[dict]:
    jwks_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/certs"
    response = _client.get(jwks_url)
    response.raise_for_status()
    return response.json().get("keys", [])

def _ensure_bytes(key: str | bytes) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return key

def _decode_value(val: str) -> int:
    decoded = base64.urlsafe_b64decode(_ensure_bytes(val) + b"==")
    return int.from_bytes(decoded, "big")

def get_public_key(kid: str) -> str | None:
    keys = _get_keycloak_public_keys()
    for key in keys:
        if key.get("kid") == kid:
            e = _decode_value(key["e"])
            n = _decode_value(key["n"])
            public_numbers = RSAPublicNumbers(e, n)
            public_key = public_numbers.public_key(default_backend())
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem
    return None

def validate_bearer(token: str) -> dict | None:
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            return None
            
        public_key = get_public_key(kid)
        if not public_key:
            return None
            
        # The issuer from Keycloak inside the mesh might be different depending on how it's configured.
        # We rely on signature verification.
        try:
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=settings.KEYCLOAK_CLIENT_ID,
                issuer=settings.KEYCLOAK_ISSUER
            )
        except (jwt.InvalidAudienceError, jwt.MissingRequiredClaimError) as exc:
            if isinstance(exc, jwt.MissingRequiredClaimError) and getattr(exc, "claim", None) != "aud":
                raise
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=settings.KEYCLOAK_ISSUER,
                options={"verify_aud": False}
            )
            if decoded.get("azp") != settings.KEYCLOAK_CLIENT_ID:
                return None
        return decoded
    except Exception:
        return None
