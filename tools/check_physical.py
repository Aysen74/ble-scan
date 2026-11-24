"""Проверка физического анализатора — короткий понятный отчёт."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.physical import PhysicalAnalyzer, MIN_TOTAL
from collector.attacks_physical import (
    scenario_clone_rssi_shift,
    scenario_legit_two_phase,
    scenario_replay_no_jitter,
    scenario_tx_power_spoof,
)
from profiles.device_profile import DeviceProfiler

VENDORS = {"0X004C": "Apple", "0X0006": "Microsoft",
           "0X0075": "Samsung", "0X00E0": "Google"}

TITLES = {
    "rssi_distribution_shift": "сигнал приходит с другого места",
    "pathloss_shift_without_rssi_shift": "заявленная мощность не сходится с сигналом",
    "timing_regularization": "пакеты идут слишком ровно — программная генерация",
    "timing_destabilization": "ритм вещания сбился",
}


def device_label(p) -> str:
    snap = p.stable_snapshot or {}
    if snap.get("local_name"):
        return str(snap["local_name"])
    for cid in (snap.get("manufacturer_data") or {}):
        return VENDORS.get(str(cid).upper(), str(cid))
    return "устройство без имени"


def load(path: Path) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_case(title: str, path: Path, expected: set) -> dict:
    records = load(path)
    profiler = DeviceProfiler(window=256)
    for r in records:
        profiler.process_record(r)
    profiles = list(profiler.profiles.values())

    analyzer = PhysicalAnalyzer()
    fired = {}
    for p in profiles:
        for a in analyzer.analyze(p):
            fired.setdefault(a["type"], []).append((p, a))

    eligible = [p for p in profiles
                if p.packet_count >= MIN_TOTAL and p.baseline_frozen]
    dup = sum(p.duplicate_count for p in profiles)

    print(f"\n=== {title} ===")
    print(f"пакетов: {len(records)} | устройств: {len(profiles)} | "
          f"дубликатов отброшено: {dup}")
    print(f"наблюдались достаточно долго: {len(eligible)} из {len(profiles)}")

    if not eligible:
        best = max((p.packet_count for p in profiles), default=0)
        print(f"!! анализ не запускался: максимум {best} пакетов, "
              f"нужно {MIN_TOTAL}. Соберите эфир 5-10 минут.")

    for t, items in fired.items():
        p, a = items[0]
        mark = "OK " if t in expected else "!! "
        print(f"{mark}{device_label(p)}: {TITLES.get(t, t)}")
        ev = a.get("evidence", {})
        if "baseline_mean_dbm" in ev:
            print(f"    сигнал: было {ev['baseline_mean_dbm']:.0f} -> "
                  f"стало {ev['current_mean_dbm']:.0f} дБм")
        if "delta_pathloss_db" in ev:
            print(f"    потери {ev['delta_pathloss_db']:+.0f} дБ, "
                  f"заявленная мощность {ev['delta_tx_db']:+.0f} дБ")
        if "baseline_cv" in ev:
            print(f"    разброс интервалов: {ev['baseline_cv']:.3f} -> "
                  f"{ev['current_cv']:.3f}")

    if not fired and eligible:
        print("аномалий нет — всё в норме")

    types = set(fired)
    return {"ok": len(types & expected),
            "extra": len(types - expected),
            "missed": len(expected - types)}


def main() -> None:
    raw = ROOT / "data" / "raw"
    results = []

    real = Path(sys.argv[1]) if len(sys.argv) > 1 else raw / "real_capture.jsonl"
    if not real.is_absolute():
        real = ROOT / real
    if real.exists():
        results.append(run_case("Реальный эфир", real, set()))
    else:
        print("Реальный эфир пропущен: файл не найден")

    cases = [
        ("Обычное устройство (проверка на ложные тревоги)",
         scenario_legit_two_phase, "phys_legit.jsonl", set()),
        ("Клон: сигнал сильнее на 18 дБ",
         scenario_clone_rssi_shift, "phys_clone_rssi.jsonl",
         {"rssi_distribution_shift"}),
        ("Replay: пакеты без естественного разброса",
         scenario_replay_no_jitter, "phys_replay.jsonl",
         {"timing_regularization"}),
        ("Подмена заявленной мощности",
         scenario_tx_power_spoof, "phys_tx_spoof.jsonl",
         {"pathloss_shift_without_rssi_shift"}),
    ]
    for title, fn, fname, expected in cases:
        path = raw / fname
        fn(str(path))
        results.append(run_case(title, path, expected))

    ok = sum(r["ok"] for r in results)
    extra = sum(r["extra"] for r in results)
    missed = sum(r["missed"] for r in results)

    print("\n=== ИТОГ ===")
    print(f"обнаружено верно: {ok}")
    print(f"ложных тревог:    {extra}")
    print(f"пропущено:        {missed}")
    if missed:
        print("подсказка: проверьте порог эталонного окна интервалов")


if __name__ == "__main__":
    main()