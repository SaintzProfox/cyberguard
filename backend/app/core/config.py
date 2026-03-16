from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "CyberGuard"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://cyberguard:cyberguard_secret@localhost:5432/cyberguard"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379"

    # Security
    SECRET_KEY: str = "change-this-secret-key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS & Hosts
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]

    # AI
    ANTHROPIC_API_KEY: Optional[str] = None

    # Email
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_NAME: str = "CyberGuard"
    EMAILS_FROM_EMAIL: str = "noreply@cyberguard.io"

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None

    # File paths
    SCAN_RESULTS_DIR: str = "/app/scan_results"
    REPORTS_DIR: str = "/app/reports"

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Subscription limits
    FREE_SCANS_LIMIT: int = 3
    MONTHLY_SCANS_LIMIT: int = 30
    PREMIUM_SCANS_LIMIT: int = 999

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
