from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[3]

class Settings(BaseSettings):
    database_url: str = f"sqlite:///{ROOT / 'rakshak.db'}"
    frontend_origin: str = "http://localhost:5173"
    upload_max_bytes: int = 5 * 1024 * 1024
    upload_max_lines: int = 50_000
    anomaly_model_path: str = str(ROOT / "data/models/isolation_forest.joblib")
    abuseipdb_api_key: str | None = None
    llm_api_key: str | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str | None = None
    llm_timeout_seconds: float = 20.0

    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore", case_sensitive=False)

settings = Settings()
