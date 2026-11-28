"""JSONL -> профили -> анализаторы -> SQLite. python tools/db_import.py <файл>"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.pipeline import evaluate
from profiles.device_profile import DeviceProfiler
from storage import db, persist


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data/raw/real_capture.jsonl"
    if not path.is_absolute():
        path = ROOT / path
    if not path.exists():
        print("Файл не найден:", path)
        return

    db.init_db()
    with open(path, "r", encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()]

    profiler = DeviceProfiler(window=256)
    profiles = profiler.process_file(path)
    decisions = evaluate(profiles)
    persist.save_profiles(profiles)
    saved = persist.save_decisions(decisions)

    with db.connect() as c:
        db.purge_old(c, days=7)
        devices = db.list_devices(c)
        alerts = db.list_alerts(c)

    print(f"Файл: {path.name}, записей: {len(records)}")
    print(f"Устройств в БД: {len(devices)}")
    print(f"Новых/обновлённых тревог: {saved}")
    print(f"Всего тревог в журнале: {len(alerts)}")
    for a in alerts[:5]:
        print(f"  [{a['level']}] {a['device']} балл {a['score']} — {a['status']}")


if __name__ == "__main__":
    main()