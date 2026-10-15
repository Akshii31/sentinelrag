"""Configuration loaded from environment variables and optional .env file."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env", override=False)


@dataclass(frozen=True)
class Settings:
    """Runtime settings; never store real secrets in source control."""

    api_key: str = ""
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = ""
    min_similarity: float = 0.10
    rate_limit_requests: int = 10
    rate_limit_window_seconds: int = 60
    max_question_chars: int = 2000
    db_path: Path = PROJECT_ROOT / "data" / "sentinelrag.db"
    data_dir: Path = PROJECT_ROOT / "data"
    llm_timeout_seconds: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        """Read settings from environment, with safe non-secret defaults."""
        try:
            min_similarity = float(os.getenv("SENTINELRAG_MIN_SIMILARITY", "0.10"))
        except ValueError as exc:
            raise ValueError("SENTINELRAG_MIN_SIMILARITY must be numeric") from exc

        try:
            rate_limit_requests = int(os.getenv("SENTINELRAG_RATE_LIMIT", "10"))
            rate_limit_window_seconds = int(os.getenv("SENTINELRAG_RATE_WINDOW_SECONDS", "60"))
            max_question_chars = int(os.getenv("SENTINELRAG_MAX_QUESTION_CHARS", "2000"))
            llm_timeout_seconds = int(os.getenv("SENTINELRAG_LLM_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise ValueError("Rate-limit, question-length, and timeout settings must be integers") from exc

        root = PROJECT_ROOT
        db_value = os.getenv("SENTINELRAG_DB_PATH", str(root / "data" / "sentinelrag.db"))
        data_value = os.getenv("SENTINELRAG_DATA_DIR", str(root / "data"))

        if not 0 <= min_similarity <= 1:
            raise ValueError("SENTINELRAG_MIN_SIMILARITY must be between 0 and 1")
        if rate_limit_requests < 1 or rate_limit_window_seconds < 1:
            raise ValueError("Rate limit and window must both be positive")
        if max_question_chars < 1 or llm_timeout_seconds < 1:
            raise ValueError("Question limit and LLM timeout must both be positive")

        return cls(
            api_key=os.getenv("SENTINELRAG_API_KEY", ""),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            llm_model=os.getenv("LLM_MODEL", ""),
            min_similarity=min_similarity,
            rate_limit_requests=rate_limit_requests,
            rate_limit_window_seconds=rate_limit_window_seconds,
            max_question_chars=max_question_chars,
            db_path=Path(db_value),
            data_dir=Path(data_value),
            llm_timeout_seconds=llm_timeout_seconds,
        )
