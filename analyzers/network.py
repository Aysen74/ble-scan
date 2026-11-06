"""
Модуль анализа сетевых метаданных (кибер-признаки).

Принимает на вход поведенческий профиль устройства и возвращает список
аномалий сетевого уровня. Каждая аномалия — словарь с типом, числовым
свидетельством, весовым коэффициентом и человекочитаемым описанием.

Важно: модуль НЕ принимает финальное решение об угрозе и НЕ генерирует
алерты. Решение принимает корреляционный движок, складывая веса кибер-
и физических аномалий. Такое разделение обеспечивает интерпретируемость
и гибридность, заявленные в научной новизне.

Реализованные детекторы соответствуют четырём признакам сетевого уровня
из главы 4 курсовой работы:
  1. advertising_interval_too_small  — интервал вещания;
  2. fingerprint_correlation         — стабильность payload при смене MAC;
  3. mac_rotation_violation          — частота/тип ротации адресов;
  4. scan_activity                   — процедуры активного сканирования
     (заглушка: SCAN_REQ/SCAN_RSP доступны только из HCI-дампа btmon).
"""

from __future__ import annotations

from typing import Any

from profiles.device_profile import DeviceProfile


# Пороги по спецификации Bluetooth Core.
BLE_ADV_INTERVAL_MIN_SEC = 0.020   # минимальный интервал advertising, 20 мс
BLE_ADV_INTERVAL_SLACK = 0.005     # допуск на случайную задержку 0..10 мс

# Начальные веса (экспертные, подлежат калибровке экспериментом).
WEIGHTS = {
    "advertising_interval_too_small": 0.6,
    "fingerprint_correlation": 0.5,
    "mac_rotation_violation": 0.3,
    "scan_activity": 0.4,
}


class NetworkAnalyzer:
    """Анализатор кибер-признаков по поведенческому профилю."""

    def __init__(self, weights: dict[str, float] | None = None):
        # Позволяет переопределить веса из config.yaml на этапе эксперимента.
        self.weights = dict(WEIGHTS)
        if weights:
            self.weights.update(weights)

    def analyze(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        """Возвращает список аномалий сетевого уровня для профиля."""
        anomalies: list[dict[str, Any]] = []
        anomalies.extend(self._detect_interval(profile))
        anomalies.extend(self._detect_fingerprint(profile))
        anomalies.extend(self._detect_rotation(profile))
        anomalies.extend(self._detect_scan(profile))
        return anomalies

    # ------------------------------------------------------------------
    # Детектор 1. Аномально малый интервал вещания (спуфинг / затопление).
    # ------------------------------------------------------------------
    def _detect_interval(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        if not profile.intervals:
            return []
        imin = min(profile.intervals)
        threshold = BLE_ADV_INTERVAL_MIN_SEC - BLE_ADV_INTERVAL_SLACK
        if imin < threshold:
            return [{
                "type": "advertising_interval_too_small",
                "value": round(imin, 4),
                "weight": self.weights["advertising_interval_too_small"],
                "level": "warning",
                "description": (
                    f"Скользящий минимум интервала {imin*1000:.1f} мс ниже "
                    f"минимума BLE ({BLE_ADV_INTERVAL_MIN_SEC*1000:.0f} мс): "
                    f"признак спуфинга или затопления."
                ),
            }]
        return []

    # ------------------------------------------------------------------
    # Детектор 2. Фингерпринтинг: стабильный payload при нескольких MAC.
    # Это НЕ атака, а уязвимость приватности (риск трекинга), как в BLENDER.
    # ------------------------------------------------------------------
    def _detect_fingerprint(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        if len(profile.mac_history) < 2:
            return []

        # Сигнатура из пустых полей тривиальна: под неё попадает любое
        # устройство без метаданных, и совпадение не означает уязвимость
        # приватности (фингерпринтинг по пустоте невозможен).
        # Срабатываем только когда есть хотя бы одно содержательное поле.
        if self._is_trivial_signature(profile.stable_snapshot):
            return []

        snap = profile.stable_snapshot or {}
        stable_desc = ", ".join(filter(None, [
            f"name={snap.get('local_name')}",
            f"tx={snap.get('tx_power_dbm')}",
            f"uuids={len(snap.get('service_uuids') or [])}",
            f"mfg={len(snap.get('manufacturer_data') or {})}",
        ]))
        return [{
            "type": "fingerprint_correlation",
            "value": len(profile.mac_history),
            "weight": self.weights["fingerprint_correlation"],
            "level": "info",
            "description": (
                f"Обнаружено {len(profile.mac_history)} MAC-адреса при одной "
                f"стабильной сигнатуре ({stable_desc}): устройство можно "
                f"трекинговать по неизменяемым полям несмотря на ротацию MAC."
            ),
        }]

    @staticmethod
    def _is_trivial_signature(snapshot: dict) -> bool:
        """True, если в снимке нет ни одного содержательного поля."""
        if not snapshot:
            return True
        has_name = bool(snapshot.get("local_name"))
        has_tx = snapshot.get("tx_power_dbm") is not None
        has_uuids = bool(snapshot.get("service_uuids"))
        has_mfg = bool(snapshot.get("manufacturer_data"))
        return not (has_name or has_tx or has_uuids or has_mfg)

    # ------------------------------------------------------------------
    # Детектор 3. Нарушение ротации адресов (публичный / застывший адрес).
    # ------------------------------------------------------------------
    def _detect_rotation(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        anomalies = []
        if "public" in profile.address_types:
            anomalies.append({
                "type": "mac_rotation_violation",
                "value": "public",
                "weight": self.weights["mac_rotation_violation"],
                "level": "warning",
                "description": (
                    "Используется публичный MAC-адрес, который не ротируется "
                    "по определению: тривиальный долгосрочный трекинг."
                ),
            })
        # Расширение на будущее: приватный адрес завис дольше 15 минут.
        # period = profile.mac_rotation_period()
        # if period is not None and period > 900 * 1.5: ...
        return anomalies

    # ------------------------------------------------------------------
    # Детектор 4. Активное сканирование (заглушка до этапа реального HCI).
    # ------------------------------------------------------------------
    def _detect_scan(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        # SCAN_REQ/SCAN_RSP не доступны через bleak на уровне хоста.
        # Реализуется парсером btmon.pcap на этапе подключения адаптера.
        # Профиль пока не накапливает scan_req_count, поэтому возвращаем пусто.
        return []