import httpx
import base64
from config import settings

_client = httpx.Client(timeout=settings.VAULT_HTTP_TIMEOUT_SECONDS)

def sign_payload(payload_bytes: bytes) -> str:
    """Signs a payload using Vault Transit and returns the raw signature"""
    url = f"{settings.VAULT_URL}/v1/transit/sign/mesh-identity"
    headers = {
        "X-Vault-Token": settings.VAULT_TOKEN
    }
    
    encoded_payload = base64.b64encode(payload_bytes).decode('utf-8')
    data = {
        "input": encoded_payload,
        "hash_algorithm": "sha2-256",
        "signature_algorithm": "pkcs1v15"
    }
    
    response = _client.post(url, headers=headers, json=data)
    response.raise_for_status()
    result = response.json()
    
    # Vault returns signature in format "vault:v1:base64_encoded_signature"
    # We strip the prefix to use it in JWS
    sig = result["data"]["signature"]
    parts = sig.split(":")
    if len(parts) >= 3:
        return parts[2]
    return sig

def get_public_keys() -> dict:
    """Gets the public keys from Vault Transit"""
    url = f"{settings.VAULT_URL}/v1/transit/keys/mesh-identity"
    headers = {
        "X-Vault-Token": settings.VAULT_TOKEN
    }
    
    response = _client.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["data"]["keys"]

def get_latest_key_version() -> str:
    """Gets the latest key version from Vault Transit"""
    url = f"{settings.VAULT_URL}/v1/transit/keys/mesh-identity"
    headers = {
        "X-Vault-Token": settings.VAULT_TOKEN
    }
    
    response = _client.get(url, headers=headers)
    response.raise_for_status()
    return str(response.json()["data"]["latest_version"])
