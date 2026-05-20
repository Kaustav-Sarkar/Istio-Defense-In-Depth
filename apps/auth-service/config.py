from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str
    
    # Keycloak
    KEYCLOAK_URL: str
    KEYCLOAK_PUBLIC_URL: str = "https://idp.localtest.me"
    KEYCLOAK_REALM: str
    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_ISSUER: str = "https://idp.localtest.me/realms/istio-security-poc"
    KEYCLOAK_TLS_VERIFY: bool = True
    
    # Vault
    VAULT_URL: str
    VAULT_TOKEN: str

    # HTTP clients
    APP_PUBLIC_URL: str = "https://app.localtest.me"
    OIDC_HTTP_TIMEOUT_SECONDS: float = 5.0
    VAULT_HTTP_TIMEOUT_SECONDS: float = 5.0

    # ExtAuthz
    ALLOWED_HOSTS: list[str] = ["*"]
    
    # App
    COOKIE_NAME: str = "zt_session"
    MESH_TOKEN_EXPIRY_MINUTES: int = 5

    class Config:
        env_file = ".env"

settings = Settings()
