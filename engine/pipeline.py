"""Прогон профилей через оба анализатора и движок."""

from __future__ import annotations

from analyzers.network import NetworkAnalyzer
from analyzers.physical import PhysicalAnalyzer, MIN_TOTAL
from engine.correlation import CorrelationEngine
from engine.settings import load_config


def evaluate(profiles: list, config: dict | None = None) -> list:
    cfg = config or load_config()
    net = NetworkAnalyzer(cfg["network_weights"] or None)
    phys = PhysicalAnalyzer(cfg["physical_weights"] or None)
    engine = CorrelationEngine(cfg)

    rows = []
    for p in profiles:
        rows.append((p, net.analyze(p), phys.analyze(p), phys.context(p)))

    # Общая интерференция: сдвиг сигнала сразу у многих устройств.
    eligible = [r for r in rows if r[0].packet_count >= MIN_TOTAL]
    shifted = sum(
        1 for r in eligible
        if any(a["type"] == "rssi_distribution_shift" for a in r[2])
    )
    interference = (
        len(eligible) >= 3
        and shifted / len(eligible) >= cfg["global_interference_share"]
    )

    decisions = []
    for p, cyber, physical, ctx in rows:
        ctx = dict(ctx)
        ctx["global_interference"] = interference
        decisions.append(engine.decide(p, cyber, physical, ctx))
    return decisions