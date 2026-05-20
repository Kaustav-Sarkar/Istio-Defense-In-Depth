import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

@patch("main.sessions.create_oauth_state")
def test_login_generates_state(mock_create_state):
    mock_create_state.return_value = "random-state-123"
    response = client.get("/auth/login", allow_redirects=False)
    
    assert response.status_code == 307
    assert "state=random-state-123" in response.headers["location"]
    mock_create_state.assert_called_once()

@patch("main.sessions.verify_oauth_state")
def test_callback_rejects_missing_or_mismatched_state(mock_verify_state):
    mock_verify_state.return_value = False
    
    response = client.get("/auth/callback?code=abc&state=invalid", allow_redirects=False)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing state"
    
    response = client.get("/auth/callback?code=abc", allow_redirects=False)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing state"

@patch("main.ext_authz.evaluate_request")
def test_verify_endpoint_vault_fail_closed(mock_evaluate, monkeypatch):
    mock_evaluate.return_value = {
        "allowed": True,
        "subject": "alice",
        "roles": ["employee"],
        "email": "alice@example.com",
        "groups": [],
        "department": "engineering",
        "audience": ["ms1"],
        "request_id": "req-123"
    }
    
    with patch("main.mesh_tokens.create_mesh_token") as mock_create_token:
        mock_create_token.side_effect = Exception("Vault signing failed")
        
        response = client.get("/verify")
        assert response.status_code == 500
        # Ensure it does not return unsigned headers
        assert "x-mesh-identity" not in response.headers


def test_verify_success_returns_mesh_identity(client, monkeypatch):
    monkeypatch.setattr(
        "main.ext_authz.evaluate_request",
        lambda *args: {"allowed": True, "reason": "ok", "audience": ["ms1"]},
    )
    monkeypatch.setattr(
        "main.mesh_tokens.create_mesh_token",
        lambda *args: "fake-jwt-token",
    )

    response = client.get("/verify", headers={"x-request-id": "123"})
    assert response.status_code == 200
    assert response.headers.get("x-mesh-identity") == "fake-jwt-token"


@patch("main.sessions.get_session")
def test_get_session_returns_full_identity(mock_get_session):
    mock_session = MagicMock()
    mock_session.id = "session-123"
    mock_session.user_id = "alice.employee"
    mock_session.username = "alice"
    mock_session.email = "alice@example.com"
    mock_session.roles = ["employee"]
    mock_session.groups = ["dev"]
    mock_session.department = "engineering"
    mock_session.created_at = "2026-05-08T00:00:00"
    mock_session.expires_at = "2026-05-08T01:00:00"
    mock_session.revoked = False
    
    mock_get_session.return_value = mock_session
    
    client.cookies.set("zt_session", "session-123")
    response = client.get("/auth/session")
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"
    assert data["email"] == "alice@example.com"
    assert data["groups"] == ["dev"]
    assert data["department"] == "engineering"
