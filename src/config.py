"""Application configuration."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_env: str = "development"
    app_name: str = "CharlottesWeb"
    debug: bool = True

    # Database
    database_url: str = "sqlite:///./charlottesweb.db"

    # API
    api_v1_prefix: str = "/api/v1"


settings = Settings()
