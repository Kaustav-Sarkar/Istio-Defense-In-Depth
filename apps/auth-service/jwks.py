import vault_client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import base64

def int_to_base64url(n: int) -> str:
    # Convert int to big-endian bytes
    byte_length = max(1, (n.bit_length() + 7) // 8)
    bytes_data = n.to_bytes(byte_length, 'big')
    return base64.urlsafe_b64encode(bytes_data).decode('utf-8').rstrip('=')

def get_jwks() -> dict:
    """Format Vault public keys as JWKS"""
    keys = vault_client.get_public_keys()
    
    jwks = {"keys": []}
    
    for version, key_info in keys.items():
        pub_key_pem = key_info["public_key"]
        
        # Parse PEM
        public_key = serialization.load_pem_public_key(pub_key_pem.encode('utf-8'))
        
        if isinstance(public_key, RSAPublicKey):
            numbers = public_key.public_numbers()
            
            jwks_key = {
                "kty": "RSA",
                "kid": str(version),
                "use": "sig",
                "alg": "RS256",
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e)
            }
            jwks["keys"].append(jwks_key)
            
    return jwks
