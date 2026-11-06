"""
Парсер AD-структур рекламных пакетов BLE.

Принимает на вход payload_hex (сырые байты AdvData в hex-виде) и
восстанавливает список AD-структур, а также плоский словарь decoded
с полями local_name, tx_power_dbm, service_uuids, manufacturer_data.

Работает только с payload_hex, не используя decoded из входной записи,
чтобы доказать корректность разбора «из байтов».
"""

from __future__ import annotations

from typing import Any


# Справочник типов AD-структур (Bluetooth Assigned Numbers, часть 6)
AD_TYPES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x16: "Service Data - 16-bit UUID",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0xFF: "Manufacturer Specific Data",
}


def _uuid16_to_full(value: int) -> str:
    return f"0000{value:04X}-0000-1000-8000-00805F9B34FB"


def _decode_ad(type_code: int, value: bytes) -> dict[str, Any]:
    """Декодирует Data-часть одной AD-структуры по её типу."""
    if type_code == 0x01:  # Flags
        flags = value[0] if value else 0
        return {
            "flags_hex": f"0x{flags:02X}",
            "limited_discoverable": bool(flags & 0x01),
            "general_discoverable": bool(flags & 0x02),
            "br_edr_not_supported": bool(flags & 0x04),
            "simultaneous_le_br_edr": bool(flags & 0x08),
        }

    if type_code in (0x08, 0x09):  # Local Name
        return {
            "name": value.decode("utf-8", errors="replace"),
            "encoding": "utf-8",
        }

    if type_code == 0x0A:  # TX Power Level (signed byte)
        if not value:
            return {}
        return {"tx_power_dbm": int.from_bytes(value[:1], "little", signed=True)}

    if type_code in (0x02, 0x03):  # 16-bit UUIDs, little-endian на проводе
        uuids = []
        for i in range(0, len(value) - 1, 2):
            uuid16 = int.from_bytes(value[i:i + 2], "little")
            uuids.append(_uuid16_to_full(uuid16))
        return {"uuids_16bit": uuids}

    if type_code in (0x04, 0x05):  # 32-bit UUIDs
        uuids = []
        for i in range(0, len(value) - 3, 4):
            uuid32 = int.from_bytes(value[i:i + 4], "little")
            uuids.append(f"{uuid32:08X}-0000-1000-8000-00805F9B34FB")
        return {"uuids_32bit": uuids}

    if type_code in (0x06, 0x07):  # 128-bit UUIDs (byte-reversed)
        uuids = []
        for i in range(0, len(value) - 15, 16):
            b = value[i:i + 16]
            uuid_str = (
                f"{b[15]:02X}{b[14]:02X}{b[13]:02X}{b[12]:02X}"
                f"-{b[11]:02X}{b[10]:02X}"
                f"-{b[9]:02X}{b[8]:02X}"
                f"-{b[7]:02X}{b[6]:02X}"
                f"-{b[5]:02X}{b[4]:02X}{b[3]:02X}{b[2]:02X}{b[1]:02X}{b[0]:02X}"
            )
            uuids.append(uuid_str)
        return {"uuids_128bit": uuids}

    if type_code == 0xFF:  # Manufacturer Specific Data
        if len(value) < 2:
            return {}
        company_id = int.from_bytes(value[:2], "little")
        return {
            "company_id": company_id,
            "company_id_hex": f"0x{company_id:04X}",
            "manufacturer_data_hex": value[2:].hex(),
        }

    if type_code in (0x16, 0x20, 0x21):  # Service Data
        size = {0x16: 2, 0x20: 4, 0x21: 16}[type_code]
        if len(value) < size:
            return {}
        return {
            "service_uuid_hex": value[:size].hex(),
            "service_data_hex": value[size:].hex(),
        }

    return {}  # неизвестный тип — оставляем только raw


def parse_ad_structures(payload_hex: str) -> list[dict[str, Any]]:
    """Разбирает payload_hex на список AD-структур."""
    data = bytes.fromhex(payload_hex)
    structures: list[dict[str, Any]] = []
    offset = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:  # padding / конец
            break
        if offset + 1 + length > len(data):
            raise ValueError(
                f"Malformed AD structure at offset {offset}: "
                f"declared length {length} exceeds buffer {len(data) - offset - 1}"
            )
        type_code = data[offset + 1]
        value = data[offset + 2:offset + 1 + length]

        structures.append({
            "offset": offset,
            "length": length + 1,          # включая байт Length
            "type_code": type_code,
            "type_name": AD_TYPES.get(type_code, f"Unknown 0x{type_code:02X}"),
            "data_hex": value.hex(),
            "decoded": _decode_ad(type_code, value),
        })
        offset += 1 + length

    return structures


def rebuild_decoded(structures: list[dict[str, Any]]) -> dict[str, Any]:
    """Собирает плоский decoded из списка AD-структур.

    Формат ключей и значений намеренно совпадает с тем, что писал
    симулятор, чтобы сверка была построчной и однозначной.
    """
    decoded: dict[str, Any] = {
        "local_name": None,
        "tx_power_dbm": None,
        "service_uuids": [],
        "manufacturer_data": {},
    }

    for s in structures:
        tc = s["type_code"]
        d = s["decoded"]

        if tc == 0x09:                       # Complete Local Name приоритетнее
            decoded["local_name"] = d.get("name")
        elif tc == 0x08 and decoded["local_name"] is None:
            decoded["local_name"] = d.get("name")

        elif tc == 0x0A:
            decoded["tx_power_dbm"] = d.get("tx_power_dbm")

        elif tc in (0x02, 0x03):
            decoded["service_uuids"].extend(d.get("uuids_16bit", []))
        elif tc in (0x04, 0x05):
            decoded["service_uuids"].extend(d.get("uuids_32bit", []))
        elif tc in (0x06, 0x07):
            decoded["service_uuids"].extend(d.get("uuids_128bit", []))

        elif tc == 0xFF:
            cid = d.get("company_id_hex")
            mdata = d.get("manufacturer_data_hex")
            if cid is not None:
                decoded["manufacturer_data"][cid] = mdata

    return decoded