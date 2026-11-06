"""
Реальный модуль сбора BLE advertising packets через bleak + WinRT/BlueZ.

Выдаёт тот же JSONL-формат, что и collector.simulator, поэтому
остальная программа (парсер, профили, анализаторы) работает без изменений.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData


def _normalize_mac(addr: str) -> str:
    return str(addr).upper()


def _normalize_addr_type(val) -> str:
    """Приводит значение типа адреса из разных бэкендов к public/random/unknown."""
    if val is None:
        return "unknown"
    s = str(val).lower()
    # WinRT enum repr: 'BluetoothAddressType.Public' / '.Random'; HCI int 0/1
    if "public" in s or s in ("0", "0.0"):
        return "public"
    if any(k in s for k in ("random", "private", "resolvable", "static")) or s in ("1", "1.0", "2", "2.0"):
        return "random"
    return "unknown"


def _extract_address_type(device: BLEDevice) -> str:
    """Кросс-бэкендно пытается достать тип адреса, не полагаясь на dict.get."""
    details = getattr(device, "details", None)

    # 1) dict-like (Linux/BlueZ, старые версии bleak)
    if isinstance(details, dict):
        for key in ("AddressType", "address-type", "address_type", "type"):
            val = details.get(key)
            if val is not None:
                return _normalize_addr_type(val)

    # 2) object with attributes (WinRT RawAdvData и т.п.)
    for attr in ("address_type", "AddressType", "address-type"):
        val = getattr(details, attr, None)
        if val is not None:
            return _normalize_addr_type(val)

    # 3) некоторые бэкенды кладут тип прямо на device
    val = getattr(device, "address_type", None)
    if val is not None:
        return _normalize_addr_type(val)

    return "unknown"


def build_record_from_bleak(device: BLEDevice, adv: AdvertisementData) -> dict:
    """Собирает JSONL-запись из события bleak в формате симулятора."""
    now = time.time()

    rssi_val = adv.rssi
    manufacturer_data = {
        f"0x{k:04X}": v.hex() for k, v in (adv.manufacturer_data or {}).items()
    }
    service_uuids = list(adv.service_uuids or [])

    return {
        "schema_version": "1.0",
        "event_type": "advertising_report",
        "timestamp_unix": now,
        "timestamp_iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "adapter": "bleak-real",
        "channel": None,                 # bleak не отдаёт номер канала напрямую
        "rssi_dbm": float(rssi_val) if rssi_val is not None else None,
        "address": _normalize_mac(device.address),
        "address_type": _extract_address_type(device),
        "ble_event_type": "ADV_IND",     # точный тип из HCI через bleak недоступен
        "connectable": True,
        "scannable": True,
        "legacy": True,
        "phy": "LE_1M",
        "payload_hex": None,             # raw payload целиком на WinRT недоступен
        "payload_length": 0,
        "decoded": {
            "local_name": adv.local_name,
            "tx_power_dbm": adv.tx_power,
            "service_uuids": service_uuids,
            "manufacturer_data": manufacturer_data,
        },
        "source": "bleak",
    }


async def run_real_capture(output_path: str, duration_sec: int = 60) -> int:
    """Непрерывно сканирует эфир и пишет JSONL-записи в output_path."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    count = 0
    errors = 0
    start = time.time()

    def callback(device: BLEDevice, adv: AdvertisementData):
        nonlocal count, errors
        try:
            rec = build_record_from_bleak(device, adv)
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
            if count % 50 == 0:
                print(f"  записано пакетов: {count}")
        except Exception as e:  # никогда не роняем цикл сканирования из-за одного пакета
            errors += 1
            if errors <= 3:
                print(f"  пропущен пакет из-за ошибки: {e!r}")

    scanner = BleakScanner(detection_callback=callback)
    await scanner.start()
    print(f"Реальный сбор запущен в {output_path}, длительность {duration_sec} сек.")

    try:
        while time.time() - start < duration_sec:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.stop()

    print(f"Готово. Записано пакетов: {count}, ошибок обработки: {errors}")
    return count


if __name__ == "__main__":
    asyncio.run(run_real_capture("data/raw/real_capture.jsonl", duration_sec=60))