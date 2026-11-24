"""
Модуль анализа физических характеристик радиосигнала.

Работает только с поведенческим профилем (без собственного состояния)
и возвращает список аномалий с весами, не принимая финального решения
об угрозе: решение принимает корреляционный движок.

Признаки:
  1. rssi_distribution_shift            — сдвиг распределения RSSI;
  2. pathloss_shift_without_rssi_shift  — несогласованность заявленной
                                          мощности и наблюдаемого уровня;
  3. timing_regularization /
     timing_destabilization             — изменение регулярности вещания.

Все статистики реализованы на стандартной библиотеке (без scipy),
что подтверждает легковесность решения.
"""

from __future__ import annotations

import math
import statistics
from typing import Any

from profiles.device_profile import DeviceProfile


MIN_SAMPLES = DeviceProfile.CALIBRATION_SIZE      # 64
MIN_TOTAL = 2 * MIN_SAMPLES                       # 128, окна не пересекаются

KS_C_ALPHA_001 = 1.63          # асимптотический коэффициент для p = 0.01

RSSI_MEAN_SHIFT_DB = 6.0
RSSI_MEAN_SHIFT_STRONG_DB = 15.0
PATHLOSS_SHIFT_DB = 8.0
RSSI_STABLE_DB = 4.0
TX_CHANGE_DB = 4.0
PATHLOSS_STABLE_DB = 3.0

CV_REGULAR_MAX = 0.03
CV_REGULAR_MIN_BASE = 0.05
CV_REGULAR_RATIO = 0.25
CV_UNSTABLE_MIN = 0.5
CV_UNSTABLE_RATIO = 3.0

WEIGHTS = {
    "rssi_distribution_shift": 0.5,
    "pathloss_shift_without_rssi_shift": 0.6,
    "timing_regularization": 0.4,
    "timing_destabilization": 0.3,
}


def ks_2samp(a: list, b: list) -> float:
    """Двухвыборочная статистика Колмогорова–Смирнова (D)."""
    if not a or not b:
        return 0.0
    a = sorted(a)
    b = sorted(b)
    n, m = len(a), len(b)
    i = j = 0
    d = 0.0
    while i < n and j < m:
        x = a[i] if a[i] <= b[j] else b[j]
        while i < n and a[i] <= x:
            i += 1
        while j < m and b[j] <= x:
            j += 1
        d = max(d, abs(i / n - j / m))
    return d


def ks_critical(n: int, m: int) -> float:
    return KS_C_ALPHA_001 * math.sqrt((n + m) / (n * m))


def coeff_variation(values: list) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean <= 0:
        return 0.0
    return statistics.pstdev(values) / mean


class PhysicalAnalyzer:
    """Анализатор физических признаков по поведенческому профилю."""

    def __init__(self, weights: dict | None = None):
        self.weights = dict(WEIGHTS)
        if weights:
            self.weights.update(weights)

    def analyze(self, profile: DeviceProfile) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        anomalies.extend(self._detect_rssi_shift(profile))
        anomalies.extend(self._detect_pathloss(profile))
        anomalies.extend(self._detect_timing(profile))
        return anomalies

    def context(self, profile: DeviceProfile) -> dict:
        """Контекст для корреляционного движка (шаг 7)."""
        return {
            "power_control_explained": self._power_control_explained(profile),
            "physical_samples_sufficient": profile.packet_count >= MIN_TOTAL,
            "baseline_frozen": profile.baseline_frozen,
        }

    # ------------------------------------------------------------------
    # Вспомогательное
    # ------------------------------------------------------------------
    @staticmethod
    def _current(values, n: int = MIN_SAMPLES) -> list:
        return list(values)[-n:]

    @staticmethod
    def _mean_or_none(values):
        return statistics.fmean(values) if values else None

    def _delta_rssi(self, profile):
        base = profile.baseline["rssi"]
        cur = self._current(profile.rssi_values)
        if len(base) < MIN_SAMPLES or len(cur) < MIN_SAMPLES:
            return None
        return statistics.fmean(cur) - statistics.fmean(base)

    def _delta_pathloss(self, profile):
        base = profile.baseline["pathloss"]
        cur = self._current(profile.pathloss_values)
        if len(base) < MIN_SAMPLES or len(cur) < MIN_SAMPLES:
            return None
        return statistics.fmean(cur) - statistics.fmean(base)

    def _delta_tx(self, profile):
        base = profile.baseline["tx"]
        cur = self._current(profile.tx_power_values)
        if len(base) < MIN_SAMPLES or len(cur) < MIN_SAMPLES:
            return None
        return statistics.fmean(cur) - statistics.fmean(base)

    def _power_control_explained(self, profile) -> bool:
        """Сдвиг RSSI объясняется легитимной адаптацией мощности.

        Если заявленная мощность изменилась, а подразумеваемые потери
        остались прежними, то изменение уровня сигнала физически
        согласовано и не является свидетельством подмены источника.
        """
        dtx = self._delta_tx(profile)
        dpl = self._delta_pathloss(profile)
        if dtx is None or dpl is None:
            return False
        return abs(dtx) >= TX_CHANGE_DB and abs(dpl) < PATHLOSS_STABLE_DB

    # ------------------------------------------------------------------
    # Признак 1. Сдвиг распределения RSSI
    # ------------------------------------------------------------------
    def _detect_rssi_shift(self, profile) -> list[dict[str, Any]]:
        if profile.packet_count < MIN_TOTAL:
            return []
        base = profile.baseline["rssi"]
        cur = self._current(profile.rssi_values)
        if len(base) < MIN_SAMPLES or len(cur) < MIN_SAMPLES:
            return []

        # Контекстная фильтрация на уровне физики.
        if self._power_control_explained(profile):
            return []

        d = ks_2samp(base, cur)
        crit = ks_critical(len(base), len(cur))
        mb = statistics.fmean(base)
        mc = statistics.fmean(cur)
        dmean = mc - mb

        agreed = d > crit and abs(dmean) >= RSSI_MEAN_SHIFT_DB
        strong = abs(dmean) >= RSSI_MEAN_SHIFT_STRONG_DB
        if not (agreed or strong):
            return []

        return [{
            "type": "rssi_distribution_shift",
            "value": round(dmean, 2),
            "weight": self.weights["rssi_distribution_shift"],
            "level": "warning",
            "description": (
                f"Распределение RSSI изменилось: эталон {mb:.1f} дБм, "
                f"текущее {mc:.1f} дБм (сдвиг {dmean:+.1f} дБ), "
                f"KS D={d:.3f} при критическом {crit:.3f}: "
                f"признак иного физического источника при той же идентичности."
            ),
            "evidence": {
                "baseline_mean_dbm": round(mb, 2),
                "current_mean_dbm": round(mc, 2),
                "delta_db": round(dmean, 2),
                "ks_d": round(d, 4),
                "ks_critical": round(crit, 4),
            },
        }]

    # ------------------------------------------------------------------
    # Признак 2. Несогласованность заявленной мощности и уровня сигнала
    # ------------------------------------------------------------------
    def _detect_pathloss(self, profile) -> list[dict[str, Any]]:
        if profile.packet_count < MIN_TOTAL:
            return []
        dpl = self._delta_pathloss(profile)
        drssi = self._delta_rssi(profile)
        dtx = self._delta_tx(profile)
        if dpl is None or drssi is None or dtx is None:
            return []

        # Уникальная диагностическая способность: потери поехали,
        # а наблюдаемый уровень сигнала остался прежним.
        if abs(dpl) >= PATHLOSS_SHIFT_DB and abs(drssi) < RSSI_STABLE_DB:
            return [{
                "type": "pathloss_shift_without_rssi_shift",
                "value": round(dpl, 2),
                "weight": self.weights["pathloss_shift_without_rssi_shift"],
                "level": "warning",
                "description": (
                    f"Подразумеваемые потери изменились на {dpl:+.1f} дБ "
                    f"при стабильном RSSI ({drssi:+.1f} дБ) и изменении "
                    f"заявленной мощности на {dtx:+.1f} дБ: несогласованность "
                    f"декларируемой мощности и наблюдаемого уровня сигнала."
                ),
                "evidence": {
                    "delta_pathloss_db": round(dpl, 2),
                    "delta_rssi_db": round(drssi, 2),
                    "delta_tx_db": round(dtx, 2),
                },
            }]
        return []

    # ------------------------------------------------------------------
    # Признак 3..Regularity таймингов
    # ------------------------------------------------------------------
    def _detect_timing(self, profile) -> list[dict[str, Any]]:
        def _detect_timing(self, profile) -> list[dict[str, Any]]:
        if profile.packet_count < MIN_TOTAL:
            return []
        base = profile.baseline["intervals"]
        cur = self._current(profile.intervals)

        # Первый пакет профиля не имеет предшествующего интервала,
        # поэтому эталонное окно интервалов на один замер короче окна RSSI.
        if len(base) < MIN_SAMPLES - 1 or len(cur) < MIN_SAMPLES:
            return []

        cv_b = coeff_variation(base)
        cv_c = coeff_variation(cur)
        anomalies = []

        # Аномальная регулярность: машинная генерация без естественного джиттера.
        if (cv_b >= CV_REGULAR_MIN_BASE
                and cv_c <= CV_REGULAR_MAX
                and cv_c <= CV_REGULAR_RATIO * cv_b):
            anomalies.append({
                "type": "timing_regularization",
                "value": round(cv_c, 4),
                "weight": self.weights["timing_regularization"],
                "level": "warning",
                "description": (
                    f"Вещание стало аномально регулярным: CV интервалов "
                    f"{cv_b:.3f} → {cv_c:.3f} (естественный джиттер исчез): "
                    f"признак программной генерации пакетов."
                ),
                "evidence": {"baseline_cv": round(cv_b, 4),
                             "current_cv": round(cv_c, 4)},
            })

        # Аномальная нерегулярность: нестабильный или конфликтующий источник.
        if (cv_b > 0 and cv_c >= CV_UNSTABLE_MIN
                and cv_c >= CV_UNSTABLE_RATIO * cv_b):
            anomalies.append({
                "type": "timing_destabilization",
                "value": round(cv_c, 4),
                "weight": self.weights["timing_destabilization"],
                "level": "info",
                "description": (
                    f"Вещание стало аномально нерегулярным: CV интервалов "
                    f"{cv_b:.3f} → {cv_c:.3f}: возможный конфликт источников "
                    f"или нестабильный передатчик."
                ),
                "evidence": {"baseline_cv": round(cv_b, 4),
                             "current_cv": round(cv_c, 4)},
            })

        return anomalies