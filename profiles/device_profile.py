"""
Поведенческий профиль BLE-устройства.

Профиль строится не по MAC-адресу, а по стабильной сигнатуре полезной
нагрузки (Device Name, Service UUIDs, Manufacturer Specific Data).

Изменения шага 6:
  - tx_power вынесен из identity-сигнатуры в физический анализ;
  - добавлены калибровочные (эталонные) окна физических метрик;
  - добавлены скользящие окна подразумеваемых потерь и заявленной мощности;
  - встроена дедупликация пакетов-дубликатов.
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

    CALIBRATION_SIZE = 64          # размер эталонного окна
    DEDUP_WINDOW_SEC = 0.010       # окно подавления дубликатов

    def __init__(self, signature: str, window: int = 256):
        self.signature = signature
        self.window = window

        self.first_seen = None
        self.last_seen = None
        self.packet_count = 0
        self.duplicate_count = 0

        self.mac_history = []
        self._mac_index = {}
        self.address_types = set()

        # Скользящие окна.
        self.timestamps = deque(maxlen=window)
        self.intervals = deque(maxlen=window)
        self.rssi_values = deque(maxlen=window)
        self.pathloss_values = deque(maxlen=window)
        self.tx_power_values = deque(maxlen=window)

        # Эталонные (калибровочные) окна: заполняются один раз в начале.
        self.baseline_frozen = False
        self.baseline = {"rssi": [], "pathloss": [], "tx": [], "intervals": []}

        self.stable_snapshot = {}

        self._last_ts = None
        self._last_mac = None
        self._last_payload_key = None

    # ------------------------------------------------------------------
    # Идентичность
    # ------------------------------------------------------------------
    @staticmethod
    def _payload_key(decoded: dict) -> tuple:
        """Нормализованный ключ идентичности (без tx_power)."""
        name = decoded.get("local_name") or ""
        uuids = tuple(sorted(decoded.get("service_uuids") or []))
        mfg = decoded.get("manufacturer_data") or {}
        mfg_norm = tuple(sorted(
            (str(k).upper(), str(v).lower()) for k, v in mfg.items()
        ))
        return (name, uuids, mfg_norm)

    @staticmethod
    def compute_signature(decoded: dict) -> str:
        """Стабильная сигнатура идентичности устройства.

        tx_power сознательно не включается: это заявленный физический
        параметр, а не идентификатор. Его изменчивость фрагментировала
        профили, а внутри профиля делала детектор потерь избыточным.
        """
        payload = json.dumps(
            DeviceProfile._payload_key(decoded),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Накопление
    # ------------------------------------------------------------------
    def update(self, record: dict) -> None:
        timestamp = float(record["timestamp_unix"])
        mac = str(record["address"]).upper()
        decoded = record.get("decoded") or {}
        key = self._payload_key(decoded)

        # Дедупликация: WinRT/BlueZ отдают один HCI-event повторно
        # (приём на нескольких advertising-каналах). Интервал 1-3 мс
        # ложно выглядит как аномально малый интервал вещания.
        if (
            self._last_ts is not None
            and timestamp - self._last_ts < self.DEDUP_WINDOW_SEC
            and mac == self._last_mac
            and key == self._last_payload_key
        ):
            self.duplicate_count += 1
            return

        rssi_raw = record.get("rssi_dbm")
        tx_raw = decoded.get("tx_power_dbm")
        rssi = float(rssi_raw) if rssi_raw is not None else None
        tx = int(tx_raw) if tx_raw is not None else None

        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.packet_count += 1

        self.address_types.add(str(record.get("address_type", "unknown")).lower())

        entry = self._mac_index.get(mac)
        if entry is None:
            entry = {"mac": mac, "first_seen": timestamp,
                     "last_seen": timestamp, "count": 0}
            self._mac_index[mac] = entry
            self.mac_history.append(entry)
        entry["last_seen"] = timestamp
        entry["count"] += 1

        interval = None
        if self._last_ts is not None:
            interval = timestamp - self._last_ts
            self.intervals.append(interval)

        self._last_ts = timestamp
        self._last_mac = mac
        self._last_payload_key = key
        self.timestamps.append(timestamp)

        if rssi is not None:
            self.rssi_values.append(rssi)
        if tx is not None:
            self.tx_power_values.append(tx)

        pathloss = None
        if rssi is not None and tx is not None:
            pathloss = float(tx) - rssi
            self.pathloss_values.append(pathloss)

        # Калибровка эталона: только первые CALIBRATION_SIZE замеров.
        if not self.baseline_frozen:
            if rssi is not None:
                self.baseline["rssi"].append(rssi)
            if tx is not None:
                self.baseline["tx"].append(tx)
            if pathloss is not None:
                self.baseline["pathloss"].append(pathloss)
            if interval is not None:
                self.baseline["intervals"].append(interval)
            if len(self.baseline["rssi"]) >= self.CALIBRATION_SIZE:
                self.baseline_frozen = True

        self.stable_snapshot = decoded

    # ------------------------------------------------------------------
    # Статистика
    # ------------------------------------------------------------------
    def interval_stats(self) -> dict:
        if not self.intervals:
            return {}
        v = list(self.intervals)
        return {
            "count": len(v),
            "mean": statistics.fmean(v),
            "min": min(v),
            "max": max(v),
            "std": statistics.pstdev(v) if len(v) > 1 else 0.0,
        }

    def rssi_stats(self) -> dict:
        if not self.rssi_values:
            return {}
        v = list(self.rssi_values)
        return {
            "count": len(v),
            "mean": statistics.fmean(v),
            "min": min(v),
            "max": max(v),
            "std": statistics.pstdev(v) if len(v) > 1 else 0.0,
        }

    def physical_summary(self) -> dict:
        """Сводка физического эталона для интерпретируемости."""
        b = self.baseline
        out = {
            "baseline_frozen": self.baseline_frozen,
            "baseline_rssi_samples": len(b["rssi"]),
            "baseline_interval_samples": len(b["intervals"]),
            "baseline_pathloss_samples": len(b["pathloss"]),
            "duplicates_suppressed": self.duplicate_count,
        }
        if b["rssi"]:
            out["baseline_rssi_mean"] = round(statistics.fmean(b["rssi"]), 2)
        if b["pathloss"]:
            out["baseline_pathloss_mean"] = round(statistics.fmean(b["pathloss"]), 2)
        if b["tx"]:
            out["baseline_tx_mean"] = round(statistics.fmean(b["tx"]), 2)
        return out

    def mac_rotation_period(self):
        if len(self.mac_history) < 2:
            return None
        starts = sorted(e["first_seen"] for e in self.mac_history)
        deltas = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
        return statistics.fmean(deltas) if deltas else None

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packet_count": self.packet_count,
            "unique_macs": len(self.mac_history),
            "mac_history": self.mac_history,
            "address_types": sorted(self.address_types),
            "stable_snapshot": self.stable_snapshot,
            "interval_stats": self.interval_stats(),
            "rssi_stats": self.rssi_stats(),
            "physical_baseline": self.physical_summary(),
            "mac_rotation_period_sec": self.mac_rotation_period(),
        }

    def save(self, path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


class DeviceProfiler:
    """Менеджер профилей: группирует пакеты по сигнатуре, а не по MAC."""

    def __init__(self, window: int = 256):
        self.window = window
        self.profiles = {}

    def process_record(self, record: dict) -> DeviceProfile:
        decoded = record.get("decoded")
        if not decoded and record.get("payload_hex"):
            decoded = rebuild_decoded(parse_ad_structures(record["payload_hex"]))
        if not decoded:
            raise ValueError("record has neither decoded nor payload_hex")

        signature = DeviceProfile.compute_signature(decoded)
        profile = self.profiles.get(signature)
        if profile is None:
            profile = DeviceProfile(signature=signature, window=self.window)
            self.profiles[signature] = profile
        profile.update(record)
        return profile

    def process_file(self, path) -> list:
        with open(Path(path), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.process_record(json.loads(line))
        return list(self.profiles.values())

    def save_all(self, out_dir) -> None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for p in self.profiles.values():
            p.save(out_dir / f"profile_{p.signature}.json")