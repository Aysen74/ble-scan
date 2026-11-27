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

        # Приоритет отображаемого имени: 0 — безымянные пакеты,
        # 1 — имя из AD-структуры Complete Local Name,
        # 2 — Shortened Local Name. Обновление более приоритетным
        # снимком гарантирует, что после слияния профилей устройство
        # покажет своё настоящее имя (например, "[TV] Samsung ..."),
        # даже если первым пришёл пакет без имени.
        self._name_rank = 0

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

    @staticmethod
    def _snapshot_rank(decoded: dict) -> int:
        """Приоритет снимка как отображаемого (чем больше, тем лучше)."""
        rank = 0
        if decoded.get("local_name"):
            rank += 10
        rank += len(decoded.get("service_uuids") or [])
        rank += len(decoded.get("manufacturer_data") or {})
        return rank

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

        # Снимок полезной нагрузки: заменяем на более «информативный» —
        # с приоритетом по наличию и типу имени, иначе по числу AD-полей.
        new_rank = self._snapshot_rank(decoded)
        if new_rank > self._name_rank or (
            new_rank == self._name_rank and not self.stable_snapshot
        ):
            self.stable_snapshot = decoded
            self._name_rank = max(self._name_rank, new_rank)
        elif not self.stable_snapshot:
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



def merge_profiles_by_mac(profiler: "DeviceProfiler") -> None:
    """Объединяет профили, которые видели один и тот же MAC-адрес.

    Профили строятся по сигнатуре полезной нагрузки, поэтому одно и то же
    устройство (например, Samsung Galaxy) может породить несколько профилей:
    часть пакетов приходит без имени/флага имени, с другим набором AD или с
    меняющимся manufacturer data. Все такие профили содержат одинаковый MAC
    в своей истории, и их нужно слить в один.

    Реализация: union-find (объединение по общим MAC). Два профиля сливаются,
    если у них есть хотя бы один общий MAC; транзитивно это объединяет целые
    группы профилей одного устройства. Внутри группы первичным выбирается
    профиль с наибольшим числом пакетов.
    """
    profiles = list(profiler.profiles.values())
    if len(profiles) < 2:
        return

    # --- Union-Find -----------------------------------------------------
    parent = list(range(len(profiles)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    # Индекс: MAC -> индекс первого профиля, его видевшего
    mac_owner: dict[str, int] = {}
    for idx, profile in enumerate(profiles):
        for entry in profile.mac_history:
            mac = str(entry.get("mac", "")).upper()
            if not mac:
                continue
            if mac in mac_owner:
                union(idx, mac_owner[mac])
            else:
                mac_owner[mac] = idx

    # --- Группировка ----------------------------------------------------
    groups: dict[int, list] = {}
    for idx, profile in enumerate(profiles):
        groups.setdefault(find(idx), []).append(profile)

    new_profiles: dict[str, DeviceProfile] = {}
    for root_idx, group in groups.items():
        if len(group) == 1:
            p = group[0]
            new_profiles[p.signature] = p
            continue

        # Первичный профиль — самый «наполненный»
        primary = max(group, key=lambda p: p.packet_count)

        merged_macs: dict[str, dict] = {}
        for secondary in group:
            if secondary is primary:
                continue
            primary.packet_count += secondary.packet_count
            primary.duplicate_count += secondary.duplicate_count
            primary.rssi_values.extend(secondary.rssi_values)
            primary.intervals.extend(secondary.intervals)
            primary.pathloss_values.extend(secondary.pathloss_values)
            primary.tx_power_values.extend(secondary.tx_power_values)
            primary.timestamps.extend(secondary.timestamps)
            primary.address_types.update(secondary.address_types)

            if secondary.first_seen is not None:
                if primary.first_seen is None or secondary.first_seen < primary.first_seen:
                    primary.first_seen = secondary.first_seen
            if secondary.last_seen is not None:
                if primary.last_seen is None or secondary.last_seen > primary.last_seen:
                    primary.last_seen = secondary.last_seen

            # mac_history: нормальное слияние без дублей записей об одном MAC
            for e in list(primary.mac_history) + list(secondary.mac_history):
                mac = str(e["mac"]).upper()
                prev = merged_macs.get(mac)
                if prev is None:
                    merged_macs[mac] = {
                        "mac": mac,
                        "first_seen": e["first_seen"],
                        "last_seen": e["last_seen"],
                        "count": e.get("count", 0),
                    }
                else:
                    prev["first_seen"] = min(prev["first_seen"], e["first_seen"])
                    prev["last_seen"] = max(prev["last_seen"], e["last_seen"])
                    prev["count"] += e.get("count", 0)

            # Эталонные окна: дополняем, пока не заморожены
            if not primary.baseline_frozen:
                for k in ("rssi", "tx", "pathloss", "intervals"):
                    for v in secondary.baseline[k]:
                        if len(primary.baseline[k]) < primary.CALIBRATION_SIZE:
                            primary.baseline[k].append(v)
                if len(primary.baseline["rssi"]) >= primary.CALIBRATION_SIZE:
                    primary.baseline_frozen = True

            # Снимок: оставляем наиболее информативный (с именем),
            # иначе вторичный заполняет пустой первичный.
            sec_rank = DeviceProfile._snapshot_rank(secondary.stable_snapshot or {})
            pri_rank = DeviceProfile._snapshot_rank(primary.stable_snapshot or {})
            if not primary.stable_snapshot or sec_rank > pri_rank:
                primary.stable_snapshot = secondary.stable_snapshot
                primary._name_rank = max(primary._name_rank, sec_rank)

        # Восстанавливаем историю MAC и индекс без дубликатов
        primary.mac_history = sorted(
            merged_macs.values(), key=lambda e: e["first_seen"]
        )
        primary._mac_index = {e["mac"]: e for e in primary.mac_history}

        new_profiles[primary.signature] = primary

    profiler.profiles = new_profiles


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
        merge_profiles_by_mac(self)
        return list(self.profiles.values())

    def save_all(self, out_dir) -> None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for p in self.profiles.values():
            p.save(out_dir / f"profile_{p.signature}.json")
