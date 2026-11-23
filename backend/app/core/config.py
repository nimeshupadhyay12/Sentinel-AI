from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAI Research Platform"
    # Intentionally required: never fall back to a predictable signing secret.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    # Short-lived access tokens; long-lived sessions use rotating refresh tokens.
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Refresh cookies are Secure by default. Browsers treat http://localhost as a
    # secure context, so local development still works; tests over plain HTTP
    # set this to false.
    COOKIE_SECURE: bool = True
    # Self-service sign-up is off by default: a SOC console should be provisioned.
    ALLOW_SELF_REGISTRATION: bool = False
    # Brute-force protection for /api/auth/login (in-process; see docs).
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15
    LOGIN_IP_MAX_ATTEMPTS: int = 30
    LOGIN_IP_WINDOW_MINUTES: int = 5

    DATABASE_URL: str = "sqlite:///./sentinelai.db"
    SENTINEL_BOOTSTRAP_ADMIN_PASSWORD: str | None = None
    SENTINEL_BOOTSTRAP_ANALYST_PASSWORD: str | None = None
    SENTINEL_BOOTSTRAP_USER_PASSWORD: str | None = None
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    # Optional base64 32-byte Ed25519 seed for audit signatures. When unset, a
    # key is derived from SECRET_KEY with HKDF so signatures survive restarts.
    AUDIT_SIGNING_KEY: str | None = None

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("SECRET_KEY must contain at least 32 characters")
        return value

    @field_validator("ALGORITHM")
    @classmethod
    def validate_algorithm(cls, value: str) -> str:
        # Only HMAC algorithms make sense with a shared SECRET_KEY; never allow
        # "none" or an asymmetric algorithm name with a symmetric key.
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("ALGORITHM must be one of HS256, HS384, HS512")
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
        # backend/.env is found regardless of the current working directory.
        env_file=(str(BACKEND_DIR / ".env"), ".env"),
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
