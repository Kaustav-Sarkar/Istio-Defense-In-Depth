import pytest
from unittest.mock import patch
from mesh_tokens import create_mesh_token
import base64
import json

@patch("mesh_tokens.vault_client.get_latest_key_version")
@patch("mesh_tokens.vault_client.sign_payload")
def test_create_mesh_token(mock_sign, mock_key_version):
    mock_sign.return_value = base64.b64encode(b"fake-signature").decode('utf-8')
    mock_key_version.return_value = "2"
    
    context = {
        "subject": "user:alice",
        "username": "alice",
        "email": "alice@example.com",
        "roles": ["employee"],
        "groups": ["eng"],
        "department": "engineering",
        "audience": ["ms1-profile-aggregator"],
        "request_id": "req-123"
    }
    
    token = create_mesh_token(context)
    
    parts = token.split(".")
    assert len(parts) == 3
    
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert header["alg"] == "RS256"
    assert header["kid"] == "2"
    
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert payload["iss"] == "auth-service"
    assert payload["sub"] == "user:alice"
    assert payload["preferred_username"] == "alice"
    assert payload["email"] == "alice@example.com"
    assert payload["roles"] == ["employee"]
    assert payload["roles_csv"] == "employee"
    assert payload["groups"] == ["eng"]
    assert payload["department"] == "engineering"
    assert payload["aud"] == ["ms1-profile-aggregator"]
    assert payload["azp"] == "auth-service"
    assert payload["act"] == {"sub": "ms1-profile-aggregator"}
    assert payload["request_id"] == "req-123"
    
    assert "iat" in payload
    assert "exp" in payload
    assert "jti" in payload
    
    ttl = payload["exp"] - payload["iat"]
    assert 120 <= ttl <= 300  # 2 to 5 minutes

@patch("mesh_tokens.vault_client.get_latest_key_version")
def test_create_mesh_token_vault_failure(mock_key_version):
    mock_key_version.side_effect = Exception("Vault unavailable")
    
    context = {"subject": "user:alice"}
    with pytest.raises(Exception):
        create_mesh_token(context)
