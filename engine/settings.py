"""Загрузка настроек: значения по умолчанию + config.json поверх них."""

from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "network_weights": {},
    "physical_weights": {},
    "warning_threshold": 0.5,
    "alert_threshold": 1.0,
    "cross_level_bonus": 1.3,
    "min_packets": 20,
    "alert_cooldown_sec": 60,
    "global_interference_share": 0.4,
}


def load_config(path=None) -> dict:
    cfg = dict(DEFAULTS)
    p = Path(path) if path else Path(__file__).resolve().parent.parent / "config.json"
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
    return cfg