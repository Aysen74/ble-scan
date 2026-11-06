"""
Симулятор BLE advertising packets.

Генерирует поток рекламных пакетов легитимного устройства в формате
JSON Lines. Использует только стандартную библиотеку Python, поэтому
работает даже без BLE-адаптера и без установленных пакетов.

Формат записи согласован с модулем сбора данных (bleak/BlueZ):
позже реальный сборщик будет выдавать такие же объекты, и вся
остальная программа (профили, анализаторы, корреляция) не изменится.
"""

import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path


# ----------------------------------------------------------------------
# Нижнеуровневые помощники: сборка AD-структур и payload
# ----------------------------------------------------------------------

def make_ad(type_code: int, data: bytes) -> bytes:
    """Собирает одну AD-структуру вида [Length][Type][Data].

    Length = 1 (байт Type) + len(Data). Спецификация: Type занимает
    ровно 1 байт, Data — от 0 до 254 байт.
    """
    if len(data) > 254:
        raise ValueError(f"AD data too long for type 0x{type_code:02X}: {len(data)}")
    return bytes([len(data) + 1, type_code]) + data


def build_adv_payload(
    name: str,
    tx_power_dbm: int,
    uuids_16: list[str],
    manufacturer_id: int,
    manufacturer_data: bytes,
) -> bytes:
    """Собирает полезную нагрузку рекламного пакета (AdvData).

    Для legacy advertising лимит — 31 байт. Если не влезает,
    имя усекаем (в реальных устройствах так и делают).
    """
    structures = []

    # 0x01 Flags: LE General Discoverable + BR/EDR Not Supported = 0x06
    structures.append(make_ad(0x01, bytes([0x06])))

    # 0x09 Complete Local Name
    name_bytes = name.encode("utf-8")
    # при необходимости урезаем имя, чтобы влезть в 31 байт
    max_name = 31 - (3 + 3 + (3 + 2 * len(uuids_16)) + (3 + 2 + len(manufacturer_data)))
    if max_name < 0:
        max_name = 0
    name_bytes = name_bytes[:max_name]
    structures.append(make_ad(0x09, name_bytes))

    # 0x0A TX Power Level (signed byte)
    structures.append(make_ad(0x0A, tx_power_dbm.to_bytes(1, "little", signed=True)))

    # 0x03 Complete List of 16-bit Service UUIDs (little-endian на проводе)
    uuid_bytes = b""
    for uuid in uuids_16:
        value = int(uuid, 16) if isinstance(uuid, str) else int(uuid)
        uuid_bytes += value.to_bytes(2, "little")
    if uuid_bytes:
        structures.append(make_ad(0x03, uuid_bytes))

    # 0xFF Manufacturer Specific Data: Company ID (LE) + произвольные байты
    mfg = manufacturer_id.to_bytes(2, "little") + manufacturer_data
    structures.append(make_ad(0xFF, mfg))

    payload = b"".join(structures)
    if len(payload) > 31:
        raise ValueError(f"Legacy advertising payload too long: {len(payload)} bytes")
    return payload


def uuid16_to_full(value: int) -> str:
    """Приводит 16-битный UUID к каноническому 128-битному виду."""
    return f"0000{value:04X}-0000-1000-8000-00805F9B34FB"


# ----------------------------------------------------------------------
# Генерация адресов
# ----------------------------------------------------------------------

def generate_random_static_mac() -> str:
    """Генерирует Random Static Address.

    По спецификации BLE у random static address два старших бита
    наиболее значащего байта равны 11. В текстовом представлении
    (AA:BB:CC:DD:EE:FF) наиболее значащий байт — первый, поэтому
    старшие биты ставим в b[0]. Также исключаем зарезервированные
    значения all-zero и all-one.
    """
    while True:
        b = bytearray(random.getrandbits(8) for _ in range(6))
        b[0] |= 0xC0  # два старших бита = 11
        if b != bytearray(6) and b != bytearray([0xFF] * 6):
            return ":".join(f"{x:02X}" for x in b)


# ----------------------------------------------------------------------
# Формирование одной записи события
# ----------------------------------------------------------------------

def build_event_record(
    timestamp_unix: float,
    address: str,
    address_type: str,
    rssi_dbm: float,
    channel: int,
    payload_hex: str,
    decoded: dict,
    ble_event_type: str = "ADV_IND",
    adapter: str = "sim0",
    source: str = "simulator",
) -> dict:
    """Собирает нормализованную запись рекламного пакета."""
    return {
        "schema_version": "1.0",
        "event_type": "advertising_report",
        "timestamp_unix": timestamp_unix,
        "timestamp_iso": datetime.fromtimestamp(
            timestamp_unix, tz=timezone.utc
        ).isoformat(),
        "adapter": adapter,
        "channel": channel,
        "rssi_dbm": round(rssi_dbm, 2),
        "address": address.upper(),
        "address_type": address_type,
        "ble_event_type": ble_event_type,
        "connectable": ble_event_type in ("ADV_IND", "ADV_DIRECT_IND"),
        "scannable": ble_event_type in ("ADV_IND", "ADV_SCAN_IND"),
        "legacy": True,
        "phy": "LE_1M",
        "payload_hex": payload_hex.lower(),
        "payload_length": len(bytes.fromhex(payload_hex)),
        # ad_structures намеренно не заполняем — это задача парсера (шаг 3)
        "decoded": decoded,
        "source": source,
    }


# ----------------------------------------------------------------------
# Основной генератор легитимного устройства
# ----------------------------------------------------------------------

def simulate_device(
    output_path: str,
    name: str = "TestSensor",
    tx_power_dbm: int = -12,
    uuids_16: list[str] | None = None,
    manufacturer_id: int = 0x004C,
    manufacturer_payload: str = "1005",
    base_rssi: float = -62.0,
    rssi_sigma: float = 2.5,
    adv_interval: float = 0.100,
    interval_jitter: float = 0.010,
    rotate_mac_period: float = 900.0,
    duration_sec: int = 30,
) -> int:
    """Генерирует поток рекламных пакетов одного легитимного устройства.

    Параметры подобраны так, чтобы поведение было похоже на реальное
    BLE-устройство: стабильные метаданные, нормальный интервал вещания
    с джиттером, RSSI с шумом, редкая ротация приватного адреса.

    Возвращает количество записанных пакетов.
    """
    if uuids_16 is None:
        uuids_16 = ["0x180D"]  # Heart Rate Service — типичный UUID датчика

    # один раз собираем payload и decoded — они стабильны у легитимного устройства
    mfg_data = bytes.fromhex(manufacturer_payload)
    payload = build_adv_payload(
        name=name,
        tx_power_dbm=tx_power_dbm,
        uuids_16=uuids_16,
        manufacturer_id=manufacturer_id,
        manufacturer_data=mfg_data,
    )
    payload_hex = payload.hex()

    decoded = {
        "local_name": name,
        "tx_power_dbm": tx_power_dbm,
        "service_uuids": [uuid16_to_full(int(u, 16)) for u in uuids_16],
        "manufacturer_data": {f"0x{manufacturer_id:04X}": manufacturer_payload},
    }

    # убеждаемся, что папка для логов существует
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    current_mac = generate_random_static_mac()
    last_mac_time = time.time()
    start = time.time()
    count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        while time.time() - start < duration_sec:
            now = time.time()

            # ротация приватного адреса (по умолчанию раз в 15 минут)
            if now - last_mac_time >= rotate_mac_period:
                current_mac = generate_random_static_mac()
                last_mac_time = now

            rssi = random.gauss(base_rssi, rssi_sigma)
            channel = random.choice([37, 38, 39])  # advertising channels

            record = build_event_record(
                timestamp_unix=now,
                address=current_mac,
                address_type="random",
                rssi_dbm=rssi,
                channel=channel,
                payload_hex=payload_hex,
                decoded=decoded,
                source="simulator",
            )

            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1

            # интервал с джиттером, но не уходить в отрицательную зону
            sleep_time = max(0.001, adv_interval + random.uniform(-interval_jitter, interval_jitter))
            time.sleep(sleep_time)

    return count