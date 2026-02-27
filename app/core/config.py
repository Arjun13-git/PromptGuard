from __future__ import annotations

import os
import secrets
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration centralized with environment-backed defaults.

    - Loads values from environment variables and a root `.env` file when present.
    - Provides runtime helpers (URLs, CORS origins) and safe defaults for local development.
    """

    # Core datastore
    MONGO_URI: str = "mongodb://localhost:27017"
    DB_NAME: str = "promptguard_db"

    # External API keys
    GROQ_API_KEY: Optional[str] = None

    # App metadata
    APP_VERSION: str = "0.0.1"

    # HTTP configuration for API and UI
    API_SCHEME: str = "http"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    STREAMLIT_SCHEME: str = "http"
    STREAMLIT_HOST: str = "127.0.0.1"
    STREAMLIT_PORT: int = 8501

    # Security & environment
    SECRET_KEY: Optional[str] = None
    ENVIRONMENT: str = "development"

    # Logging & runtime
    LOG_LEVEL: str = "INFO"

    # Comma-separated CORS origins (useful in production). If empty, we'll compute sensible defaults.
    CORS_ORIGINS: Optional[str] = None

    # pydantic-settings config
    # - `extra: 'ignore'` prevents unknown environment variables from raising errors
    #   (some deployment environments inject unrelated vars).
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    @field_validator("MONGO_URI", mode="before")
    @classmethod
    def _read_mongo_alias(cls, v):
        """Allow the legacy env var `MONGO_URL` to override `MONGO_URI` when present."""
        if v:
            return v
        legacy = os.getenv("MONGO_URL")
        if legacy:
            return legacy
        return v

    @field_validator("SECRET_KEY", mode="before")
    @classmethod
    def _ensure_secret(cls, v):
        """Generate a dev secret if none provided to make local runs frictionless."""
        if v:
            return v
        if os.getenv("ENVIRONMENT", "development") != "production":
            return secrets.token_urlsafe(32)
        # In production require explicitly set SECRET_KEY
        return v

    def api_base_url(self) -> str:
        return f"{self.API_SCHEME}://{self.API_HOST}:{self.API_PORT}"

    def streamlit_base_url(self) -> str:
        return f"{self.STREAMLIT_SCHEME}://{self.STREAMLIT_HOST}:{self.STREAMLIT_PORT}"

    def cors_origins_list(self) -> List[str]:
        """Return list of allowed CORS origins.

        Priority:
        1. `CORS_ORIGINS` env var (comma-separated)
        2. Sensible defaults including API and Streamlit hosts during development
        """
        if self.CORS_ORIGINS:
            parts = [p.strip() for p in self.CORS_ORIGINS.split(",") if p.strip()]
            return parts

        # Default to allowing the API and Streamlit origins on local dev.
        origins = [self.api_base_url(), self.streamlit_base_url()]
        # Also allow localhost forms
        origins.extend([
            f"http://localhost:{self.API_PORT}",
            f"http://localhost:{self.STREAMLIT_PORT}",
        ])
        return list(dict.fromkeys(origins))

    def redacted(self) -> dict:
        """Return a serializable dict of settings with secrets redacted for safe logging."""
        d = self.model_dump()
        if "SECRET_KEY" in d and d["SECRET_KEY"]:
            d["SECRET_KEY"] = "<redacted>"
        if "GROQ_API_KEY" in d and d["GROQ_API_KEY"]:
            d["GROQ_API_KEY"] = "<redacted>"
        return d


settings = Settings()


# Backwards-compatible aliases used by older modules
MONGO_URL = settings.MONGO_URI
DB_NAME = settings.DB_NAME
GROQ_API_KEY = settings.GROQ_API_KEY


def api_base_url() -> str:
    return settings.api_base_url()


def streamlit_base_url() -> str:
    return settings.streamlit_base_url()


# Convenience for other modules that want CORS origin list directly
def cors_origins() -> List[str]:
    return settings.cors_origins_list()
