from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAI Research Platform"
    # Intentionally required: never fall back to a predictable signing secret.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DATABASE_URL: str = "sqlite:///./sentinelai.db"
    SENTINEL_BOOTSTRAP_ADMIN_PASSWORD: str | None = None
    SENTINEL_BOOTSTRAP_ANALYST_PASSWORD: str | None = None
    SENTINEL_BOOTSTRAP_USER_PASSWORD: str | None = None
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("SECRET_KEY must contain at least 32 characters")
        return value

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, value):
        if not value:
            return "sqlite:///./sentinelai.db"
        if isinstance(value, str) and value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql://", 1)
        return value

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="allow",
        case_sensitive=True,
    )


settings = Settings()
