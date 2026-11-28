"""Сохранение профилей и решений движка в SQLite."""

from __future__ import annotations

from storage import db

VENDORS = {"0X004C": "Apple", "0X0075": "Samsung", "0X0006": "Microsoft",
           "0X0D23": "Gree", "0X07D0": "Tuya", "0X00E0": "Google"}


def vendor_of(snapshot: dict) -> str:
    for cid in (snapshot or {}).get("manufacturer_data", {}):
        s = str(cid).upper()
        s = "0X" + s[2:].zfill(4) if s.startswith("0X") else s
        if s in VENDORS:
            return VENDORS[s]
    return "Unknown"


def save_profiles(profiles):
    with db.connect() as c:
        for p in profiles:
            db.upsert_device(c, p, vendor_of(p.stable_snapshot))
            db.observe(c, p)


def save_decisions(decisions):
    saved = 0
    with db.connect() as c:
        for d in decisions:
            if d["level"] == "none":
                db.auto_resolve(c, d["signature"])
                continue
            if db.upsert_alert(c, d):
                saved += 1
    return saved