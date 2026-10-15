"""Command-line viewer for SentinelRAG audit events."""

import argparse

from app.config import Settings
from app.db import AuditLogError, AuditLogger


def main() -> None:
    parser = argparse.ArgumentParser(description="View SentinelRAG audit logs")
    parser.add_argument("--limit", type=int, default=20, help="Number of recent entries (1–500)")
    parser.add_argument("--flagged-only", action="store_true", help="Show only blocked injection attempts")
    args = parser.parse_args()

    settings = Settings.from_env()
    try:
        logger = AuditLogger(settings.db_path)
        rows = logger.recent(limit=args.limit, flagged_only=args.flagged_only)
    except AuditLogError:
        print("Audit log is unavailable.")
        return
    if not rows:
        print("No audit entries found.")
        return

    print(f"Showing {len(rows)} audit event(s):\n")
    for row in rows:
        print(
            f"#{row['id']} | {row['ts']} | decision={row['decision']} | HTTP {row['status_code']} | "
            f"mode={row['mode']} | flagged={bool(row['flagged'])} | "
            f"reason={row['reason'] or '-'} | score={row['similarity']}"
        )
        print(f"  Question: {row['question'][:180]}")
        if row["answer_snippet"]:
            print(f"  Result: {row['answer_snippet'][:180]}")
        print()


if __name__ == "__main__":
    main()
