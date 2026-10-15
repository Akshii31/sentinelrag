"""SQLite audit logging with redacted, bounded request and response previews."""

from pathlib import Path
import re
import sqlite3
from threading import Lock
from typing import Any


class AuditLogError(RuntimeError):
    """Raised when SentinelRAG cannot reliably persist or read audit events."""


_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")
_NAMED_SECRET = re.compile(
    r"(?i)\b(api[ _-]?key|password|token|secret)\s*[:=]\s*[^\s,;]+"
)
_OPENAI_STYLE_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")


def safe_preview(value: str, limit: int) -> str:
    """Return a compact log preview with common personal data and secrets redacted."""
    preview = " ".join(value.split())
    preview = _EMAIL.sub("[redacted-email]", preview)
    preview = _PHONE.sub("[redacted-phone]", preview)
    preview = _NAMED_SECRET.sub(r"\1=[redacted]", preview)
    preview = _OPENAI_STYLE_KEY.sub("[redacted-secret]", preview)
    return preview[:limit]


class AuditLogger:
    """Persist safe request-decision records in a project-local SQLite database."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._lock = Lock()
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                        key_fingerprint TEXT,
                        decision TEXT NOT NULL,
                        question TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        status_code INTEGER NOT NULL,
                        flagged INTEGER NOT NULL DEFAULT 0,
                        reason TEXT NOT NULL DEFAULT '',
                        similarity REAL,
                        answer_snippet TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(requests)")
                }
                if "decision" not in columns:
                    connection.execute(
                        "ALTER TABLE requests ADD COLUMN decision TEXT NOT NULL DEFAULT 'legacy'"
                    )
                connection.execute("CREATE INDEX IF NOT EXISTS idx_requests_flagged ON requests(flagged)")
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise AuditLogError("Audit log initialization failed") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def log_request(
        self,
        *,
        key_fingerprint: str | None,
        decision: str,
        question: str,
        mode: str,
        status_code: int,
        flagged: bool = False,
        reason: str = "",
        similarity: float | None = None,
        answer_snippet: str = "",
    ) -> int:
        """Persist a bounded event or explicitly report an audit availability failure."""
        try:
            with self._lock, self._connect() as connection:
                cursor = connection.execute(
                    """INSERT INTO requests
                       (key_fingerprint, decision, question, mode, status_code, flagged, reason,
                        similarity, answer_snippet)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        key_fingerprint,
                        decision[:50],
                        safe_preview(question, 500),
                        mode[:20],
                        int(status_code),
                        int(flagged),
                        reason[:100],
                        similarity,
                        safe_preview(answer_snippet, 500),
                    ),
                )
                connection.commit()
                return int(cursor.lastrowid)
        except (OSError, sqlite3.Error) as exc:
            raise AuditLogError("Audit log write failed") from exc

    def recent(self, limit: int = 50, flagged_only: bool = False) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        query = "SELECT * FROM requests"
        params: tuple[Any, ...] = ()
        if flagged_only:
            query += " WHERE flagged = 1"
        query += " ORDER BY id DESC LIMIT ?"
        params += (limit,)
        try:
            with self._lock, self._connect() as connection:
                rows = connection.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        except (OSError, sqlite3.Error) as exc:
            raise AuditLogError("Audit log query failed") from exc

    def close(self) -> None:
        """No persistent connection is held; included for lifecycle clarity."""
        return None
