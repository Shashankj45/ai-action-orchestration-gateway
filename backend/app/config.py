"""
app/config.py

Centralised settings using Pydantic Settings.
All configuration is loaded from environment variables / .env file.

Security note:
- Settings are validated at startup. Missing required vars cause an immediate
  crash with a clear error — fail-fast approach prevents silent misconfigurations.
- DATABASE_URL, LLM_API_KEY, and JWT_SECRET_KEY are never exposed in API responses or logs.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, AnyHttpUrl
from typing import List, Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_env: str = "development"
    secret_key: str
    allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    allowed_hosts: str = "*"

    # Database
    database_url: str = "sqlite:///./gateway.db"

    # LLM
    llm_provider: str = "openai"
    llm_api_key: str = "placeholder"
    llm_model: str = "gpt-4o-mini"

    # Security / limits
    max_request_size: int = 10_485_760   # 10 MB
    rate_limit_per_minute: int = 60
    external_api_timeout: int = 30       # seconds

    # Inbound Authentication & JWT (Phase 10A)
    jwt_secret_key: str
    jwt_issuer: str = "guardrailed-ai-gateway"
    jwt_audience: str = "guardrailed-ai-gateway-api"
    jwt_access_token_expire_minutes: int = 15
    initial_admin_username: str = "admin"
    initial_admin_password: Optional[str] = None

    # Recruiter Demo Mode (backend-controlled, per-session isolated sandbox)
    demo_mode_enabled: bool = True
    demo_session_ttl_hours: int = 24
    demo_max_active_sessions: int = 50
    demo_max_actions_per_session: int = 30
    demo_login_limit_per_5min: int = 15
    demo_task_limit_per_minute: int = 15

    @field_validator("secret_key")
    @classmethod
    def secret_key_must_be_set(cls, v: str) -> str:
        if not v or v.startswith("change-this"):
            raise ValueError(
                "SECRET_KEY must be set to a secure random value. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @field_validator("jwt_secret_key")
    @classmethod
    def jwt_secret_key_must_be_secure(cls, v: str) -> str:
        if not v or len(v) < 32 or v.startswith("change-this"):
            raise ValueError(
                "JWT_SECRET_KEY must be set to a cryptographically secure random value of at least 32 characters (256 bits)."
            )
        return v

    @field_validator("app_env")
    @classmethod
    def app_env_must_be_valid(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v

    @property
    def cors_origins(self) -> List[str]:
        """Parse comma-separated ALLOWED_ORIGINS into a list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


# Singleton — import this everywhere
settings = Settings()
