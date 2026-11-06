"""
Быстрая проверка результата симулятора: читает JSONL,
печатает первые записи и сводную статистику.
"""

import json
from collections import defaultdict
from pathlib import Path


def load_records(path: str) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main() -> None:
    path = "data/raw/capture.jsonl"
    if not Path(path).exists():
        print("Файл не найден. Сначала запустите: python main.py")
        return

    records = load_records(path)
    print(f"Всего записей: {len(records)}")
    print("\n--- первые 3 записи ---")
    for r in records[:3]:
        print(json.dumps(r, ensure_ascii=False, indent=2))

    # сводная статистика по MAC
    by_mac = defaultdict(list)
    for r in records:
        by_mac[r["address"]].append(r)

    print("\n--- статистика по устройствам ---")
    for mac, recs in by_mac.items():
        rssis = [x["rssi_dbm"] for x in recs]
        ts = sorted(x["timestamp_unix"] for x in recs)
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        print(
            f"MAC={mac}  пакетов={len(recs)}  "
            f"RSSI среднее={sum(rssis)/len(rssis):.1f}  "
            f"мин.интервал={min(intervals)*1000:.1f} мс  "
            f"name={recs[0]['decoded']['local_name']}"
        )


if __name__ == "__main__":
    main()