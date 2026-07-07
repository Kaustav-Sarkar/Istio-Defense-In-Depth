import pytest
from unittest.mock import patch, MagicMock
from fastapi import Request
from ext_authz import evaluate_request

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_bearer_allowed(mock_validate):
    mock_validate.return_value = {"sub": "alice", "realm_access": {"roles": ["employee"]}, "email": "alice@example.com"}
    
    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        return default
        
    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    # Mocking ExtAuthz path headers or FastAPI url
    request.url.path = "/api/profile/alice"
    request.method = "GET"
    
    db = MagicMock()
    
    decision = evaluate_request(request, db)
    
    assert decision["allowed"] is True
    assert decision["subject"] == "alice"
    assert "employee" in decision["roles"]

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_uses_original_path_with_verify_prefix(mock_validate):
    mock_validate.return_value = {"sub": "alice", "realm_access": {"roles": ["employee"]}, "email": "alice@example.com"}

    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        if key == "x-envoy-original-path":
            return "/api/profile/alice"
        if key == "x-envoy-original-method":
            return "GET"
        return default

    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    request.url.path = "/verify/api/profile/alice"
    request.method = "GET"

    decision = evaluate_request(request, MagicMock())

    assert decision["allowed"] is True
    assert decision["audience"] == ["ms1-profile-aggregator", "ms2-employee-details", "ms3-hardware-assets"]

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_normalizes_verify_prefixed_path(mock_validate):
    mock_validate.return_value = {"sub": "alice", "realm_access": {"roles": ["employee"]}, "email": "alice@example.com"}

    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        return default

    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    request.url.path = "/verify/api/profile/alice"
    request.method = "GET"

    decision = evaluate_request(request, MagicMock())

    assert decision["allowed"] is True
    assert decision["audience"] == ["ms1-profile-aggregator", "ms2-employee-details", "ms3-hardware-assets"]

@patch("ext_authz.sessions.get_session")
def test_evaluate_request_cookie_allowed(mock_get_session):
    mock_session = MagicMock()
    mock_session.user_id = "bob"
    mock_session.roles = ["manager"]
    mock_session.email = "bob@example.com"
    mock_session.groups = ["sales"]
    mock_session.department = "sales"
    mock_get_session.return_value = mock_session
    
    request = MagicMock(spec=Request)
    request.headers.get.return_value = None
    request.cookies.get.return_value = "valid-session-id"
    request.url.path = "/api/profile/bob"
    request.method = "GET"
    
    db = MagicMock()
    
    decision = evaluate_request(request, db)
    
    assert decision["allowed"] is True
    assert decision["subject"] == "bob"
    assert "manager" in decision["roles"]

def test_evaluate_request_no_auth():
    request = MagicMock(spec=Request)
    request.headers.get.return_value = None
    request.cookies.get.return_value = None
    request.url.path = "/api/profile/alice"
    request.method = "GET"
    
    db = MagicMock()
    
    decision = evaluate_request(request, db)
    
    assert decision["allowed"] is False
    assert decision.get("subject") is None

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_it_admin_profile_allowed(mock_validate):
    mock_validate.return_value = {
        "sub": "ivan",
        "realm_access": {"roles": ["employee", "it_admin"]},
        "email": "ivan.itadmin@example.com",
    }

    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        return default

    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    request.url.path = "/api/profile/alice"
    request.method = "GET"

    decision = evaluate_request(request, MagicMock())

    assert decision["allowed"] is True
    assert "it_admin" in decision["roles"]
    assert decision["audience"] == [
        "ms1-profile-aggregator",
        "ms2-employee-details",
        "ms3-hardware-assets",
    ]

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_unauthorized_route_role(mock_validate):
    mock_validate.return_value = {"sub": "alice", "realm_access": {"roles": ["employee"]}}

    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        return default

    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    request.url.path = "/api/holidays"
    request.method = "POST"

    decision = evaluate_request(request, MagicMock())

    assert decision["allowed"] is False
    assert decision.get("reason") == "Unauthorized role for route"

@patch("ext_authz.oidc.validate_bearer")
def test_evaluate_request_offices_not_in_policy_map(mock_validate):
    mock_validate.return_value = {"sub": "alice", "realm_access": {"roles": ["public_data_admin"]}}

    def mock_headers_get(key, default=None):
        if key == "authorization":
            return "Bearer valid-token"
        return default

    request = MagicMock(spec=Request)
    request.headers.get.side_effect = mock_headers_get
    request.url.path = "/api/offices"
    request.method = "POST"

    decision = evaluate_request(request, MagicMock())

    assert decision["allowed"] is False
    assert decision.get("reason") == "Route not defined in coarse policy map"
