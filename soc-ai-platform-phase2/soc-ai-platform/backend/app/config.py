"""Application settings, loaded from environment variables / .env (never hard-code secrets)."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SOC AI Platform"
    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "soc_platform"
    use_mock_db: bool = False  # in-memory MongoDB mock (tests / offline demo only)

    jwt_secret: str = "CHANGE_ME_IN_ENV"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    wazuh_webhook_token: str = ""  # shared secret for /api/ingest/wazuh; empty = endpoint disabled
    cors_origins: str = "http://localhost:5173"

    max_body_bytes: int = 5 * 1024 * 1024
    max_batch_events: int = 1000
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    event_retention_days: int = 90  # TTL on security_events.ingested_at


@lru_cache
def get_settings() -> Settings:
    return Settings()
