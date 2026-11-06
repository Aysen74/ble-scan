"""
Генераторы вредоносных BLE-потоков для экспериментального стенда.

Это НЕ часть рабочего инструмента, а средства имитации атак для
проверки детекторов. Формат записей совпадает с collector.simulator,
поэтому весь остальной конвейер (парсер, профили, анализаторы)
работает без изменений.

Реализованные сценарии:
  - fast_interval_advancing : спуфинг/затопление (интервал ниже нормы BLE);
  - rotating_mac_fingerprint: устройство ротирует MAC при стабильном payload
                              (риск трекинга, сценарий BLENDER);
  - static_public_address   : публичный адрес не ротируется (тривиальный трекинг).
"""

from __future__ import annotations

import random
import time
from pathlib import Path

from collector.simulator import (
    build_adv_payload,
    build_event_record,
    generate_random_static_mac,
    uuid16_to_full,
)


def _public_mac() -> str:
    """Генерирует публичный MAC: два старших бита первого байта = 00."""
    b = bytearray(random.getrandbits(8) for _ in range(6))
    b[0] &= 0x3F  # сбрасываем два старших бита в 00 -> public address
    return ":".join(f"{x:02X}" for x in b)


def _stable_payload_and_decoded(name: str, mfg_id: int, mfg_hex: str,
                                tx: int, uuid16: str):
    payload = build_adv_payload(
        name=name, tx_power_dbm=tx, uuids_16=[uuid16],
        manufacturer_id=mfg_id, manufacturer_data=bytes.fromhex(mfg_hex),
    )
    decoded = {
        "local_name": name,
        "tx_power_dbm": tx,
        "service_uuids": [uuid16_to_full(int(uuid16, 16))],
        "manufacturer_data": {f"0x{mfg_id:04X}": mfg_hex},
    }
    return payload.hex(), decoded


def attack_fast_interval(output_path: str, duration_sec: int = 5,
                         adv_interval: float = 0.005) -> int:
    """Спуфинг/затопление: пакеты чаще минимума BLE (20 мс)."""
    payload_hex, decoded = _stable_payload_and_decoded(
        "SpoofNode", 0x00E0, "abcd", -8, "0x180F")  # 0x180F = Battery Service
    mac = generate_random_static_mac()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        while time.time() - start < duration_sec:
            now = time.time()
            rec = build_event_record(
                timestamp_unix=now, address=mac, address_type="random",
                rssi_dbm=random.gauss(-50, 3.0), channel=random.choice([37, 38, 39]),
                payload_hex=payload_hex, decoded=decoded, source="attack_fast_interval",
            )
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
            time.sleep(max(0.001, adv_interval + random.uniform(-0.002, 0.002)))
    return count


def attack_rotating_mac(output_path: str, duration_sec: int = 5,
                        adv_interval: float = 0.050,
                        rotate_mac_period: float = 0.5) -> int:
    """Риск трекинга: стабильный payload, MAC меняется часто."""
    payload_hex, decoded = _stable_payload_and_decoded(
        "TrackableBand", 0x027C, "112233", -10, "0x180D")
    mac = generate_random_static_mac()
    last_mac_time = time.time()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        while time.time() - start < duration_sec:
            now = time.time()
            if now - last_mac_time >= rotate_mac_period:
                mac = generate_random_static_mac()
                last_mac_time = now
            rec = build_event_record(
                timestamp_unix=now, address=mac, address_type="random",
                rssi_dbm=random.gauss(-62, 2.5), channel=random.choice([37, 38, 39]),
                payload_hex=payload_hex, decoded=decoded, source="attack_rotating_mac",
            )
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
            time.sleep(max(0.001, adv_interval + random.uniform(-0.005, 0.005)))
    return count


def attack_static_public(output_path: str, duration_sec: int = 5,
                         adv_interval: float = 0.100) -> int:
    """Тривиальный трекинг: публичный MAC не ротируется."""
    payload_hex, decoded = _stable_payload_and_decoded(
        "LegacySensor", 0x0006, "9988", -12, "0x180A")  # 0x180A = Device Info
    mac = _public_mac()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        while time.time() - start < duration_sec:
            now = time.time()
            rec = build_event_record(
                timestamp_unix=now, address=mac, address_type="public",
                rssi_dbm=random.gauss(-60, 2.0), channel=random.choice([37, 38, 39]),
                payload_hex=payload_hex, decoded=decoded, source="attack_static_public",
            )
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
            time.sleep(max(0.001, adv_interval + random.uniform(-0.010, 0.010)))
    return count


import json  # noqa: E402  (используется выше в f.write)