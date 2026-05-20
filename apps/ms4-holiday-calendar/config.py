from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = (
        "postgresql+asyncpg://ms4_user:ms4_secure_pass@localhost:5432/hr_directory"
    )
    CERBOS_URL: str = "http://cerbos.zt-security.svc.cluster.local:3592"
    CERBOS_TIMEOUT_SECONDS: float = 2.0

    class Config:
        env_file = ".env"

settings = Settings()
