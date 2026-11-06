"""
Проверка модуля анализа сетевых метаданных.

Принимает путь к JSONL-файлу как аргумент командной строки.
Если аргумент не задан — использует data/raw/capture.jsonl (симулятор).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.network import NetworkAnalyzer
from profiles.device_profile import DeviceProfiler


def load_records(path: Path) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def build_profiles(records: list[dict]) -> list:
    profiler = DeviceProfiler(window=256)
    for r in records:
        profiler.process_record(r)
    return list(profiler.profiles.values())


def run_case(title: str, records: list[dict],
             expected_types: set[str]) -> dict:
    analyzer = NetworkAnalyzer()
    profiles = build_profiles(records)
    fired: dict[str, list] = {}
    for p in profiles:
        for a in analyzer.analyze(p):
            fired.setdefault(a["type"], []).append(a)

    fired_types = set(fired.keys())
    tp = len(fired_types & expected_types)
    fp = len(fired_types - expected_types)
    fn = len(expected_types - fired_types)

    print(f"\n=== {title} ===")
    print(f"профилей: {len(profiles)}, типов аномалий: {sorted(fired_types) or '—'}")
    for t, items in fired.items():
        mark = "OK" if t in expected_types else "НЕОЖИДАННО"
        print(f"  [{mark}] {t}: {len(items)} срабатываний, "
              f"пример: {items[0]['description'][:120]}")
    if not fired:
        print("  аномалий нет")
    print(f"итог сценария: TP={tp} FP={fp} FN={fn}")
    return {"case": title, "tp": tp, "fp": fp, "fn": fn,
            "fired": sorted(fired_types), "expected": sorted(expected_types)}


def main() -> None:
    if len(sys.argv) > 1:
        capture_path = Path(sys.argv[1])
        if not capture_path.is_absolute():
            capture_path = ROOT / capture_path
    else:
        capture_path = ROOT / "data" / "raw" / "capture.jsonl"

    if not capture_path.exists():
        print(f"Файл не найден: {capture_path}")
        print("Использование: python tools/check_network.py <путь_к_jsonl>")
        return

    print(f"Читаю файл: {capture_path}")
    records = load_records(capture_path)
    print(f"Записей в файле: {len(records)}")

    # Прогоняем только указанный файл — без автогенерации атак
    result = run_case(
        f"реальный сбор: {capture_path.name}",
        records,
        set(),  # на реальном фоне ожидаем 0 аномалий (проверка FPR)
    )

    print("\n================ СВОДКА ================")
    print(f"{'сценарий':<60}{'TP':>4}{'FP':>4}{'FN':>4}")
    print(f"{result['case']:<60}{result['tp']:>4}{result['fp']:>4}{result['fn']:>4}")


if __name__ == "__main__":
    main()