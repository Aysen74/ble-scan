"""
Корреляционный движок.

Складывает веса кибер- и физических аномалий, гасит объяснимые
отклонения и выносит решение: уровень, балл, причины.
"""

from __future__ import annotations

from engine.settings import load_config

VENDORS = {"0X004C": "Apple", "0X0006": "Microsoft",
           "0X0075": "Samsung", "0X00E0": "Google"}


def device_label(profile) -> str:
    snap = profile.stable_snapshot or {}
    if snap.get("local_name"):
        return str(snap["local_name"])
    for cid in (snap.get("manufacturer_data") or {}):
        return VENDORS.get(str(cid).upper(), str(cid))
    return "устройство без имени"


class CorrelationEngine:
    def __init__(self, config: dict | None = None):
        self.cfg = config or load_config()

    def decide(self, profile, cyber: list, physical: list,
               context: dict | None = None) -> dict:
        ctx = context or {}

        if profile.packet_count < self.cfg["min_packets"]:
            return self._empty(profile, reason="мало данных")

        cyber = list(cyber)
        physical = list(physical)

        # Контекстная фильтрация.
        if ctx.get("power_control_explained"):
            physical = [a for a in physical
                        if a["type"] != "rssi_distribution_shift"]
        if ctx.get("global_interference"):
            physical = [a for a in physical
                        if a["type"] not in ("rssi_distribution_shift",
                                             "timing_destabilization")]

        score = sum(a["weight"] for a in cyber + physical)
        if cyber and physical:
            score *= self.cfg["cross_level_bonus"]
        score = round(score, 2)

        if score >= self.cfg["alert_threshold"]:
            level = "alert"
        elif score >= self.cfg["warning_threshold"]:
            level = "warning"
        elif score > 0:
            level = "info"
        else:
            level = "none"

        return {
            "signature": profile.signature,
            "device": device_label(profile),
            "packet_count": profile.packet_count,
            "last_seen": profile.last_seen,
            "level": level,
            "score": score,
            "cross_level": bool(cyber and physical),
            "cyber_types": [a["type"] for a in cyber],
            "physical_types": [a["type"] for a in physical],
            "reasons": [
                {"type": a["type"], "weight": a["weight"],
                 "description": a["description"],
                 "evidence": a.get("evidence", {})}
                for a in cyber + physical
            ],
            "context": ctx,
        }

    @staticmethod
    def _empty(profile, reason="") -> dict:
        return {
            "signature": profile.signature,
            "device": device_label(profile),
            "packet_count": profile.packet_count,
            "last_seen": profile.last_seen,
            "level": "none", "score": 0.0, "cross_level": False,
            "cyber_types": [], "physical_types": [],
            "reasons": [], "context": {"note": reason},
        }