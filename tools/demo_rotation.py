"""
Демонстрация ротации MAC-адресов.

Генерирует короткий поток пакетов устройства, которое часто меняет
MAC-адрес, но сохраняет стабильную полезную нагрузку.

Затем показывает, что DeviceProfiler объединяет все эти пакеты
в один профиль по сигнатуре.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collector.simulator import simulate_device
from profiles.device_profile import DeviceProfiler


def main() -> None:
    output_path = ROOT / "data" / "raw" / "capture_rotation.jsonl"

    print("Генерирую устройство с ускоренной ротацией MAC ...")
    print("Это демонстрационный режим: в реальном BLE ротация обычно около 15 минут.")

    n = simulate_device(
        output_path=str(output_path),
        name="RotatingSensor",
        base_rssi=-60.0,
        rssi_sigma=2.0,
        adv_interval=0.020,
        interval_jitter=0.003,
        rotate_mac_period=0.4,
        duration_sec=3,
    )

    print(f"Записано пакетов: {n}")

    profiler = DeviceProfiler(window=256)
    profiles = profiler.process_file(output_path)

    print(f"Построено профилей: {len(profiles)}")

    for profile in profiles:
        d = profile.to_dict()

        print("\n--- профиль ротационного устройства ---")
        print(f"signature: {d['signature']}")
        print(f"packets: {d['packet_count']}")
        print(f"unique MACs: {d['unique_macs']}")
        print(f"mac_rotation_period_sec: {d['mac_rotation_period_sec']}")
        print(f"stable name: {d['stable_snapshot'].get('local_name')}")

        print("MAC history:")
        for mac_entry in d["mac_history"]:
            print(
                f"  {mac_entry['mac']}  "
                f"count={mac_entry['count']}  "
                f"first_seen={mac_entry['first_seen']:.3f}  "
                f"last_seen={mac_entry['last_seen']:.3f}"
            )

    profiler.save_all(ROOT / "data" / "profiles")
    print("\nПрофили сохранены в data/profiles/")


if __name__ == "__main__":
    main()