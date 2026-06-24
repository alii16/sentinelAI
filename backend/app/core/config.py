"""
Sentinel AI - Core Configuration
"""
from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List
import json
import os


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Sentinel AI"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Database
    MYSQL_HOST: str = "localhost"
    MYSQL_PORT: int = 3306
    MYSQL_DATABASE: str = "sentinel_ai"
    MYSQL_USERNAME: str = "root"
    MYSQL_PASSWORD: str = ""

    # JWT
    JWT_SECRET: str = "sentinel-ai-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "null",
    ]
    
    # Scanner
    PLAYWRIGHT_TIMEOUT: int = 10000
    MAX_WORKERS: int = 5
    MAX_DEPTH: int = 5
    MAX_PAGES: int = 1000
    SCAN_DELAY_MS: int = 100
    RATE_LIMIT_RPS: int = 5

    # Paths
    REPORT_PATH: str = "reports/"
    DATASET_PATH: str = "datasets/"
    MODEL_PATH: str = "models/saved/"
    SCREENSHOT_PATH: str = "storage/screenshots/"
    UPLOAD_PATH: str = "storage/uploads/"

    # AI
    ANTHROPIC_API_KEY: str = ""
    AI_MODEL: str = "claude-sonnet-4-6"
    # Provider selection: 'groq', 'anthropic', or 'google'
    AI_PROVIDER: str = "groq"

    # Groq API configuration
    GROQ_API_KEY: str = "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"
    GROQ_MODEL: str = "llama-3.1-8b-instant"

    # Google Generative Language API (optional)
    GOOGLE_API_KEY: str = ""
    GOOGLE_MODEL: str = "text-bison-001"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def DATABASE_URL(self) -> str:
        return (
            f"mysql+asyncmy://{self.MYSQL_USERNAME}:{self.MYSQL_PASSWORD}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"
            f"?charset=utf8mb4"
        )

    @property
    def SYNC_DATABASE_URL(self) -> str:
        return (
            f"mysql+pymysql://{self.MYSQL_USERNAME}:{self.MYSQL_PASSWORD}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DATABASE}"
            f"?charset=utf8mb4"
        )

    model_config = {"env_file": ".env", "case_sensitive": True, "extra": "ignore"}


settings = Settings()
