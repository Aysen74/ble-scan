"""Проверка корреляционного движка — короткий отчёт."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzers.physical import MIN_TOTAL
from collector.attacks_physical import (
    scenario_clone_combined,
    scenario_clone_rssi_shift,
    scenario_legit_two_phase,
    scenario_replay_no_jitter,
    scenario_tx_power_spoof,
)
from engine.pipeline import evaluate
from engine.settings import load_config
from profiles.device_profile import DeviceProfiler
from storage.alert_manager import AlertManager

LEVELS = {"none": "норма", "info": "замечание",
          "warning": "ПРЕДУПРЕЖДЕНИЕ", "alert": "ТРЕВОГА"}

SHORT = {
    "advertising_interval_too_small": "вещает чаще нормы BLE",
    "fingerprint_correlation": "узнаётся по данным при смене адреса",
    "mac_rotation_violation": "адрес не меняется",
    "rssi_distribution_shift": "сигнал приходит с другого места",
    "pathloss_shift_without_rssi_shift": "мощность не сходится с сигналом",
    "timing_regularization": "пакеты идут слишком ровно",
    "timing_destabilization": "ритм вещания сбился",
}


def run_case(title, path, expect_alert):
    with open(path, "r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    profiler = DeviceProfiler(window=256)
    for r in records:
        profiler.process_record(r)
    profiles = list(profiler.profiles.values())
    decisions = evaluate(profiles, load_config())

    ready = sum(1 for p in profiles if p.packet_count >= MIN_TOTAL)
    print(f"\n=== {title} ===")
    print(f"устройств: {len(profiles)} | данных достаточно: {ready}")

    active = [d for d in decisions if d["level"] != "none"]
    if not active:
        print("норма — ничего не выявлено")
    for d in sorted(active, key=lambda x: -x["score"]):
        print(f"{LEVELS[d['level']]}  {d['device']}  балл {d['score']}")
        for r in d["reasons"]:
            print(f"   - {SHORT.get(r['type'], r['type'])} (вес {r['weight']})")
        if d["cross_level"]:
            print("   + совпали сетевой и физический признаки")

    has_alert = any(d["level"] == "alert" for d in decisions)
    ok = has_alert == expect_alert
    print("итог:", "верно" if ok else "ОШИБКА")
    return ok, has_alert


def main() -> None:
    raw = ROOT / "data" / "raw"
    alerts = AlertManager(ROOT / "data" / "alerts" / "alerts.jsonl",
                          load_config()["alert_cooldown_sec"])
    results = []

    real = raw / "real_capture.jsonl"
    if real.exists():
        results.append(run_case("Реальный эфир", real, False))

    cases = [
        ("Обычное устройство", scenario_legit_two_phase, "phys_legit.jsonl", False),
        ("Клон: сигнал сильнее", scenario_clone_rssi_shift, "phys_clone_rssi.jsonl", False),
        ("Replay: ровные интервалы", scenario_replay_no_jitter, "phys_replay.jsonl", False),
        ("Подмена мощности", scenario_tx_power_spoof, "phys_tx_spoof.jsonl", False),
        ("Клон + частое вещание", scenario_clone_combined, "phys_combined.jsonl", True),
    ]
    for title, fn, fname, expect in cases:
        path = raw / fname
        fn(str(path))
        results.append(run_case(title, path, expect))
        with open(path, "r", encoding="utf-8") as f:
            recs = [json.loads(line) for line in f if line.strip()]
        pr = DeviceProfiler(window=256)
        for r in recs:
            pr.process_record(r)
        for d in evaluate(list(pr.profiles.values()), load_config()):
            alerts.publish(d)

    good = sum(1 for ok, _ in results if ok)
    print("\n=== ИТОГ ===")
    print(f"сценариев проверено: {len(results)}")
    print(f"решения верные:      {good}")
    print(f"ошибок:              {len(results) - good}")
    print(f"тревог записано:     {alerts.saved} (data/alerts/alerts.jsonl)")


if __name__ == "__main__":
    main()