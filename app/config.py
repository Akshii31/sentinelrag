"""Configuration loaded from environment variables and optional .env file."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import dotenv_values

from app.security import api_key_is_configured

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _configured_value(name: str, file_values: dict[str, str | None], default: str = "") -> str:
    """Resolve a setting from a usable process value or this project's `.env`.

    A non-empty process variable remains the explicit override. For the server
    API key, an empty or example placeholder process value must not mask a
    usable value stored in the project-root `.env` file.
    """
    process_value = os.getenv(name)
    if name == "SENTINELRAG_API_KEY":
        if process_value is not None and api_key_is_configured(process_value):
            return process_value
    elif process_value is not None and process_value.strip():
        return process_value

    file_value = file_values.get(name)
    if file_value is not None:
        return file_value
    return process_value if process_value is not None else default


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
        """Read settings using the fixed project-root `.env` path.

        This function deliberately does not depend on the current working
        directory, so `uvicorn app.main:app` started from the project root and
        IDE launch configurations resolve the same `.env` file.
        """
        file_values = dotenv_values(PROJECT_ROOT / ".env")
        try:
            min_similarity = float(
                _configured_value("SENTINELRAG_MIN_SIMILARITY", file_values, "0.10")
            )
        except ValueError as exc:
            raise ValueError("SENTINELRAG_MIN_SIMILARITY must be numeric") from exc

        try:
            rate_limit_requests = int(
                _configured_value("SENTINELRAG_RATE_LIMIT", file_values, "10")
            )
            rate_limit_window_seconds = int(
                _configured_value("SENTINELRAG_RATE_WINDOW_SECONDS", file_values, "60")
            )
            max_question_chars = int(
                _configured_value("SENTINELRAG_MAX_QUESTION_CHARS", file_values, "2000")
            )
            llm_timeout_seconds = int(
                _configured_value("LLM_TIMEOUT_SECONDS", file_values, "30")
            )
        except ValueError as exc:
            raise ValueError("Rate-limit, question-length, and timeout settings must be integers") from exc

        root = PROJECT_ROOT
        db_value = _configured_value(
            "SENTINELRAG_DB_PATH", file_values, str(root / "data" / "sentinelrag.db")
        )
        data_value = _configured_value("SENTINELRAG_DATA_DIR", file_values, str(root / "data"))

        if not 0 <= min_similarity <= 1:
            raise ValueError("SENTINELRAG_MIN_SIMILARITY must be between 0 and 1")
        if rate_limit_requests < 1 or rate_limit_window_seconds < 1:
            raise ValueError("Rate limit and window must both be positive")
        if max_question_chars < 1 or llm_timeout_seconds < 1:
            raise ValueError("Question limit and LLM timeout must both be positive")

        return cls(
            api_key=_configured_value("SENTINELRAG_API_KEY", file_values),
            llm_api_key=_configured_value("LLM_API_KEY", file_values),
            llm_base_url=_configured_value(
                "LLM_BASE_URL", file_values, "https://api.openai.com/v1"
            ).rstrip("/"),
            llm_model=_configured_value("LLM_MODEL", file_values),
            min_similarity=min_similarity,
            rate_limit_requests=rate_limit_requests,
            rate_limit_window_seconds=rate_limit_window_seconds,
            max_question_chars=max_question_chars,
            db_path=Path(db_value),
            data_dir=Path(data_value),
            llm_timeout_seconds=llm_timeout_seconds,
        )
