"""Точка входа проекта ble_privacy_tool.

Режимы работы:
  python main.py                          — симуляция 20 сек (по умолчанию)
  python main.py --real                   — реальный сбор 180 сек
  python main.py --real --duration 60     — реальный сбор 60 сек
  python main.py --sim --duration 10      — симуляция 10 сек
  python main.py --output data/raw/my.jsonl  — свой путь к файлу
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
from pathlib import Path


def _default_output(suffix: str) -> str:
    """Генерирует имя файла с меткой времени, чтобы не перезаписывать старые."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"data/raw/capture_{stamp}{suffix}"


def run_simulation(args: argparse.Namespace) -> None:
    from collector.simulator import simulate_device

    output = args.output or _default_output(".jsonl")
    print(f"[симуляция] Запись в {output}, длительность {args.duration} с ...")
    n = simulate_device(
        output_path=output,
        name="TestSensor",
        base_rssi=-62.0,
        adv_interval=0.100,
        duration_sec=args.duration,
    )
    print(f"[симуляция] Готово. Записано пакетов: {n}")


def run_real(args: argparse.Namespace) -> None:
    from collector.acquisition_bleak import run_real_capture

    output = args.output or _default_output("_real.jsonl")
    print(f"[реальный сбор] Запись в {output}, длительность {args.duration} с ...")
    print("  Положите телефон/устройство рядом с адаптером UB500.")
    print("  Нажмите Ctrl+C для досрочной остановки.")
    n = asyncio.run(run_real_capture(output, duration_sec=args.duration))
    print(f"[реальный сбор] Готово. Записано пакетов: {n}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Сбор BLE advertising packets: симуляция или реальный эфир."
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--real", action="store_true",
        help="собирать реальный BLE-трафик через bleak + UB500",
    )
    mode.add_argument(
        "--sim", action="store_true",
        help="генерировать синтетический трафик (по умолчанию, если не указан --real)",
    )
    p.add_argument(
        "--duration", type=int, default=None,
        help="длительность сбора в секундах "
             "(по умолчанию: 20 для симуляции, 180 для реального сбора)",
    )
    p.add_argument(
        "--output", type=str, default=None,
        help="путь к выходному JSONL-файлу "
             "(по умолчанию: data/raw/capture_<timestamp>.jsonl)",
    )
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Если длительность не задана явно — берём разумный дефолт по режиму.
    if args.duration is None:
        args.duration = 180 if args.real else 20

    if args.real:
        run_real(args)
    else:
        run_simulation(args)


if __name__ == "__main__":
    main()