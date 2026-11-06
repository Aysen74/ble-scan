"""
Проверка построения поведенческих профилей BLE-устройств.

Принимает путь к JSONL-файлу как аргумент командной строки.
Если аргумент не задан — использует data/raw/capture.jsonl (симулятор).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from profiles.device_profile import DeviceProfiler


def print_profile(profile_dict: dict) -> None:
    print("\n--- профиль ---")
    print(f"signature: {profile_dict['signature']}")
    print(f"packets: {profile_dict['packet_count']}")
    print(f"unique MACs: {profile_dict['unique_macs']}")
    print(f"first_seen: {profile_dict['first_seen']}")
    print(f"last_seen: {profile_dict['last_seen']}")

    stable = profile_dict.get("stable_snapshot", {})
    print(f"stable name: {stable.get('local_name')}")
    print(f"stable tx_power_dbm: {stable.get('tx_power_dbm')}")
    print(f"stable service_uuids: {stable.get('service_uuids')}")
    print(f"stable manufacturer_data: {stable.get('manufacturer_data')}")

    print(f"interval_stats: {profile_dict.get('interval_stats')}")
    print(f"rssi_stats: {profile_dict.get('rssi_stats')}")
    print(f"mac_rotation_period_sec: {profile_dict.get('mac_rotation_period_sec')}")

    print("MAC history:")
    for mac_entry in profile_dict.get("mac_history", []):
        print(
            f"  {mac_entry['mac']}  "
            f"count={mac_entry['count']}  "
            f"first_seen={mac_entry['first_seen']:.3f}  "
            f"last_seen={mac_entry['last_seen']:.3f}"
        )


def main() -> None:
    # Путь к файлу: либо из argv, либо по умолчанию (симулятор)
    if len(sys.argv) > 1:
        capture_path = Path(sys.argv[1])
        if not capture_path.is_absolute():
            capture_path = ROOT / capture_path
    else:
        capture_path = ROOT / "data" / "raw" / "capture.jsonl"

    if not capture_path.exists():
        print(f"Файл не найден: {capture_path}")
        print("Использование: python tools/check_profiles.py <путь_к_jsonl>")
        print("Пример:        python tools/check_profiles.py data/raw/real_capture.jsonl")
        return

    print(f"Читаю файл: {capture_path}")

    profiler = DeviceProfiler(window=256)
    profiles = profiler.process_file(capture_path)

    total_packets = sum(profile.packet_count for profile in profiles)

    print(f"Обработано записей: {total_packets}")
    print(f"Построено профилей: {len(profiles)}")

    # Сортируем профили по числу пакетов — крупные устройства будут сверху
    profiles.sort(key=lambda p: p.packet_count, reverse=True)

    for profile in profiles:
        print_profile(profile.to_dict())

    profiles_dir = ROOT / "data" / "profiles"
    profiler.save_all(profiles_dir)
    print(f"\nПрофили сохранены в: {profiles_dir}")


if __name__ == "__main__":
    main()