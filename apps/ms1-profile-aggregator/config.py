from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MS2_BASE_URL: str = "http://ms2-employee-details.zt-apps.svc.cluster.local:8000"
    MS3_BASE_URL: str = "http://ms3-hardware-assets.zt-apps.svc.cluster.local:8000"
    DOWNSTREAM_TIMEOUT_SECONDS: float = 5.0

    class Config:
        env_file = ".env"

settings = Settings()
