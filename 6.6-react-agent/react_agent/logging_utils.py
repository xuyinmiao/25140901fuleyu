from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


class RunLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def reset(self) -> None:
        self.path.write_text("", encoding="utf-8")

    def write(self, title: str, body: str = "") -> None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(f"\n===== {title} [{timestamp}] =====\n")
            if body:
                fh.write(body.rstrip() + "\n")

    def append(self, body: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(body.rstrip() + "\n")
