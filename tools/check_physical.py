"""
Проверка модуля анализа физических характеристик.

P1 — реальный эфир (ожидаем отсутствие аномалий на легитимном фоне);
P2 — две фазы легитимного устройства (ожидаем 0);
P3 — клон со сдвигом RSSI (ожидаем rssi_distribution_shift);
P4 — replay без джиттера (ожидаем timing_regularization);
P5 — подмена заявленной мощности (ожидаем pathloss_shift_without_rssi_shift).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.physical import PhysicalAnalyzer
from collector.attacks_physical import (
    scenario_clone_rssi_shift,
    scenario_legit_two_phase,
    scenario_replay_no_jitter,
    scenario_tx_power_spoof,
)
from profiles.device_profile import DeviceProfiler


def load_records(path: Path) -> list:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def run_case(title: str, path: Path, expected: set) -> dict:
    records = load_records(path)
    profiler = DeviceProfiler(window=256)
    for r in records:
        profiler.process_record(r)
    profiles = list(profiler.profiles.values())

    analyzer = PhysicalAnalyzer()
    fired = {}
    for p in profiles:
        for a in analyzer.analyze(p):
            fired.setdefault(a["type"], []).append(a)

    types = set(fired)
    tp = len(types & expected)
    fp = len(types - expected)
    fn = len(expected - types)

    print(f"\n=== {title} ===")
    print(f"записей: {len(records)}, профилей: {len(profiles)}, "
          f"типов аномалий: {sorted(types) or '—'}")
    for t, items in fired.items():
        mark = "OK" if t in expected else "НЕОЖИДАННО"
        print(f"  [{mark}] {t}: {len(items)}")
        print(f"      {items[0]['description']}")
    if not fired:
        print("  аномалий нет")
    for p in profiles:
        s = p.physical_summary()
        print(f"  профиль {p.signature}: пакетов={p.packet_count}, "
              f"дубликатов подавлено={s['duplicates_suppressed']}, "
              f"эталон RSSI={s.get('baseline_rssi_mean')} дБм "
              f"({s['baseline_rssi_samples']} замеров)")
    print(f"итог: TP={tp} FP={fp} FN={fn}")
    return {"case": title, "tp": tp, "fp": fp, "fn": fn}


def main() -> None:
    raw = ROOT / "data" / "raw"
    results = []

    real = raw / "real_capture.jsonl"
    if real.exists():
        results.append(run_case("P1 реальный эфир (легитимный фон)", real, set()))
    else:
        print("P1 пропущен: нет data/raw/real_capture.jsonl")

    cases = [
        ("P2 легитимное устройство, две фазы", scenario_legit_two_phase,
         "phys_legit.jsonl", set()),
        ("P3 клон: сдвиг RSSI +18 дБ", scenario_clone_rssi_shift,
         "phys_clone_rssi.jsonl", {"rssi_distribution_shift"}),
        ("P4 replay: исчезновение джиттера", scenario_replay_no_jitter,
         "phys_replay.jsonl", {"timing_regularization"}),
        ("P5 подмена заявленной мощности", scenario_tx_power_spoof,
         "phys_tx_spoof.jsonl", {"pathloss_shift_without_rssi_shift"}),
    ]
    for title, fn, fname, expected in cases:
        path = raw / fname
        n = fn(str(path))
        print(f"\n[{fname}] сгенерировано пакетов: {n}")
        results.append(run_case(title, path, expected))

    print("\n================ СВОДКА ================")
    print(f"{'сценарий':<46}{'TP':>4}{'FP':>4}{'FN':>4}")
    tp = fp = fn_ = 0
    for r in results:
        print(f"{r['case']:<46}{r['tp']:>4}{r['fp']:>4}{r['fn']:>4}")
        tp += r["tp"]; fp += r["fp"]; fn_ += r["fn"]
    print(f"{'ИТОГО':<46}{tp:>4}{fp:>4}{fn_:>4}")
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn_) if (tp + fn_) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print(f"\nPrecision={prec:.2f}  Recall={rec:.2f}  F1={f1:.2f}")
    print("(по типам детекторов на сценарий, не по пакетам)")


if __name__ == "__main__":
    main()