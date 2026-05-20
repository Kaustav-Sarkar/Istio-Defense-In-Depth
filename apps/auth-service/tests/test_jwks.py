import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwks import get_jwks

@patch("jwks.vault_client.get_public_keys")
def test_get_jwks(mock_get_keys):
    # Generate a real RSA key for the test
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    mock_get_keys.return_value = {
        "1": {
            "public_key": pem
        }
    }
    
    jwks = get_jwks()
    
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    assert jwks["keys"][0]["kty"] == "RSA"
    assert jwks["keys"][0]["kid"] == "1"
    assert "n" in jwks["keys"][0]
    assert "e" in jwks["keys"][0]
