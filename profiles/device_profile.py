"""
Поведенческий профиль BLE-устройства.

Ключевая идея: профиль строится не по MAC-адресу, а по стабильной
сигнатуре полезной нагрузки рекламных пакетов.

Сигнатура вычисляется по полям, которые обычно не меняются при
ротации MAC-адресов:
- local_name;
- service_uuids;
- manufacturer_data;
- tx_power_dbm.

Это позволяет относить пакеты с разными MAC-адресами к одному
логическому устройству, если их стабильные метаданные совпадают.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import deque
from pathlib import Path

from parser.ad_parser import parse_ad_structures, rebuild_decoded


class DeviceProfile:
    """Поведенческий профиль одного логического BLE-устройства."""

    def __init__(self, signature: str, window: int = 256):
        self.signature = signature
        self.window = window

        self.first_seen = None
        self.last_seen = None
        self.packet_count = 0

        # История MAC-адресов, наблюдавшихся с этой сигнатурой.
        # Каждый элемент: {"mac": ..., "first_seen": ..., "last_seen": ..., "count": ...}
        self.mac_history = []
        self._mac_index = {}

        # Скользящие окна для статистики.
        self.timestamps = deque(maxlen=window)
        self.intervals = deque(maxlen=window)
        self.rssi_values = deque(maxlen=window)

        # Стабильные поля, по которым построена сигнатура.
        # Храним для интерпретируемости будущих алертов.
        self.stable_snapshot = {}

        self._last_ts = None
        
        self.address_types = set()

    @staticmethod
    def compute_signature(decoded: dict) -> str:
        """Вычисляет стабильную сигнатуру устройства по decoded-полям.

        Важно использовать hashlib, а не встроенный hash(), потому что
        hash() для строк в Python зависит от PYTHONHASHSEED и даёт
        разные значения в разных запусках программы.
        """
        name = decoded.get("local_name") or ""

        tx_power = decoded.get("tx_power_dbm")
        tx_power = int(tx_power) if tx_power is not None else 0

        uuids = sorted(decoded.get("service_uuids") or [])

        manufacturer_data = decoded.get("manufacturer_data") or {}
        manufacturer_normalized = sorted(
            (str(company_id).upper(), str(data).lower())
            for company_id, data in manufacturer_data.items()
        )

        signature_payload = json.dumps(
            {
                "local_name": name,
                "tx_power_dbm": tx_power,
                "service_uuids": uuids,
                "manufacturer_data": manufacturer_normalized,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

        return hashlib.sha256(signature_payload.encode("utf-8")).hexdigest()[:16]

    def update(self, record: dict) -> None:
        """Добавляет один рекламный пакет в профиль."""
        timestamp = float(record["timestamp_unix"])
        mac = str(record["address"]).upper()
        if (
            self._last_ts is not None
            and timestamp - self._last_ts < 0.010
            and mac in self._mac_index
            and record.get("decoded") == self.stable_snapshot
        ):
            return
        rssi_raw = record.get("rssi_dbm")

        if self.first_seen is None:
            self.first_seen = timestamp

        self.last_seen = timestamp
        self.packet_count += 1

        # Обновляем историю MAC-адресов.
        mac_entry = self._mac_index.get(mac)
        if mac_entry is None:
            mac_entry = {
                "mac": mac,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "count": 0,
            }
            self._mac_index[mac] = mac_entry
            self.mac_history.append(mac_entry)

        mac_entry["last_seen"] = timestamp
        mac_entry["count"] += 1

        # Считаем интервал от предыдущего пакета.
        if self._last_ts is not None:
            self.intervals.append(timestamp - self._last_ts)

        self._last_ts = timestamp
        self.timestamps.append(timestamp)
        if rssi_raw is not None:
            self.rssi_values.append(float(rssi_raw))
        # Сохраняем стабильные поля для интерпретации.
        self.stable_snapshot = record.get("decoded", {})
        self.address_types.add(str(record.get("address_type", "unknown")).lower())

    def interval_stats(self) -> dict:
        """Статистика по интервалам вещания в скользящем окне."""
        if not self.intervals:
            return {}

        values = list(self.intervals)

        return {
            "count": len(values),
            "mean": statistics.fmean(values),
            "min": min(values),
            "max": max(values),
            "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
        }

    def rssi_stats(self) -> dict:
        """Статистика по RSSI в скользящем окне."""
        if not self.rssi_values:
            return {}

        values = list(self.rssi_values)

        return {
            "count": len(values),
            "mean": statistics.fmean(values),
            "min": min(values),
            "max": max(values),
            "std": statistics.pstdev(values) if len(values) > 1 else 0.0,
        }

    def mac_rotation_period(self):
        """Средний период смены MAC-адресов для этой сигнатуры.

        Если MAC один, возвращает None.
        """
        if len(self.mac_history) < 2:
            return None

        starts = sorted(entry["first_seen"] for entry in self.mac_history)
        deltas = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]

        if not deltas:
            return None

        return statistics.fmean(deltas)

    def to_dict(self) -> dict:
        """Преобразует профиль в словарь для сохранения в JSON."""
        return {
            "signature": self.signature,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "unique_macs": len(self.mac_history),
            "mac_history": self.mac_history,
            "stable_snapshot": self.stable_snapshot,
            "interval_stats": self.interval_stats(),
            "rssi_stats": self.rssi_stats(),
            "mac_rotation_period_sec": self.mac_rotation_period(),
        }

    def save(self, path: str | Path) -> None:
        """Сохраняет профиль в JSON-файл."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


class DeviceProfiler:
    """Менеджер профилей устройств.

    Группирует пакеты по стабильной сигнатуре, а не по MAC-адресу.
    """

    def __init__(self, window: int = 256):
        self.window = window
        self.profiles = {}

    def process_record(self, record: dict) -> DeviceProfile:
        """Обрабатывает одну запись рекламного пакета."""
        decoded = record.get("decoded")

        # Если decoded нет, но есть payload_hex, восстанавливаем decoded
        # через парсер AD-структур.
        if not decoded and record.get("payload_hex"):
            structures = parse_ad_structures(record["payload_hex"])
            decoded = rebuild_decoded(structures)

        if not decoded:
            raise ValueError("record has neither decoded nor payload_hex")

        signature = DeviceProfile.compute_signature(decoded)

        profile = self.profiles.get(signature)
        if profile is None:
            profile = DeviceProfile(signature=signature, window=self.window)
            self.profiles[signature] = profile

        profile.update(record)
        return profile

    def process_file(self, path: str | Path) -> list[DeviceProfile]:
        """обрабатывает весь JSONL-файл и возвращает список профилей."""
        path = Path(path)

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    self.process_record(record)

        return list(self.profiles.values())

    def save_all(self, out_dir: str | Path) -> None:
        """Сохраняет все профили в отдельную папку."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        for profile in self.profiles.values():
            profile.save(out_dir / f"profile_{profile.signature}.json")