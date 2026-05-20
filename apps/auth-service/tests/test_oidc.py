from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from oidc import get_login_url, validate_bearer
from config import settings
import jwt


_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_PEM = (
    _private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
)


def test_get_login_url():
    url = get_login_url("https://app.localtest.me/callback", state="random-state")
    assert "protocol/openid-connect/auth" in url
    assert "redirect_uri=https%3A%2F%2Fapp.localtest.me%2Fcallback" in url or "redirect_uri=https://app.localtest.me/callback" in url
    assert "state=random-state" in url

def test_get_login_url_uses_public_idp_host():
    url = get_login_url("https://app.localtest.me/auth/callback", state="random-state")
    assert url.startswith("https://idp.localtest.me/realms/test-realm/protocol/openid-connect/auth")

def test_validate_bearer_real_decode(monkeypatch):
    monkeypatch.setattr("oidc.get_public_key", lambda *args: _PUBLIC_PEM)

    token = jwt.encode(
        {
            "sub": "user1",
            "aud": settings.KEYCLOAK_CLIENT_ID,
            "iss": settings.KEYCLOAK_ISSUER,
            "realm_access": {"roles": ["employee"]},
        },
        _private_key,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )

    result = validate_bearer(token)
    assert result is not None
    assert result["sub"] == "user1"

@patch("oidc.jwt.get_unverified_header")
@patch("oidc.get_public_key")
def test_validate_bearer_invalid_issuer_audience(mock_get_key, mock_get_header):
    mock_get_header.return_value = {"kid": "key123"}
    mock_get_key.return_value = "fake-pem"
    
    # We shouldn't mock jwt.decode completely, we should let it raise InvalidIssuerError 
    # to simulate strict validation. But since we need a signed token for `jwt.decode`,
    # we can mock `jwt.decode` to raise `jwt.InvalidIssuerError` or `jwt.InvalidAudienceError`.
    with patch("oidc.jwt.decode", side_effect=jwt.InvalidIssuerError):
        result = validate_bearer("fake.jwt.token")
        assert result is None
        
    with patch("oidc.jwt.decode", side_effect=jwt.InvalidAudienceError):
        result = validate_bearer("fake.jwt.token")
        assert result is None

@patch("oidc.jwt.get_unverified_header")
@patch("oidc.get_public_key")
def test_validate_bearer_accepts_keycloak_azp_without_audience(mock_get_key, mock_get_header):
    mock_get_header.return_value = {"kid": "key123"}
    mock_get_key.return_value = "fake-pem"

    with patch(
        "oidc.jwt.decode",
        side_effect=[
            jwt.InvalidAudienceError,
            {"sub": "alice", "azp": "test-client", "realm_access": {"roles": ["employee"]}},
        ],
    ):
        result = validate_bearer("fake.jwt.token")

    assert result is not None
    assert result["sub"] == "alice"

@patch("oidc.jwt.get_unverified_header")
def test_validate_bearer_invalid_token(mock_get_header):
    mock_get_header.side_effect = Exception("Invalid token")
    assert validate_bearer("invalid") is None
