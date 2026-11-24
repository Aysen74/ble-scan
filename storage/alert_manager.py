"""Запись тревог в JSONL с защитой от повторов."""

from __future__ import annotations

import json
from pathlib import Path


class AlertManager:
    def __init__(self, path="data/alerts/alerts.jsonl", cooldown_sec=60):
        self.path = Path(path)
        self.cooldown = cooldown_sec
        self._last = {}
        self.saved = 0

    def publish(self, decision: dict) -> bool:
        if decision["level"] not in ("warning", "alert"):
            return False
        key = decision["signature"]
        now = decision.get("last_seen") or 0
        if key in self._last and now - self._last[key] < self.cooldown:
            return False
        self._last[key] = now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision, ensure_ascii=False) + "\n")
        self.saved += 1
        return True