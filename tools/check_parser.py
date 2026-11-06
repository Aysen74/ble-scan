"""
Проверка парсера AD-структур на данных симулятора.

Для каждой записи capture.jsonl:
  1) разбирает payload_hex -> ad_structures;
  2) собирает из них recovered_decoded;
  3) сверяет с эталонным decoded симулятора по 4 полям.

Парсер работает только с payload_hex, decoded используется как эталон.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# --- якорь на корень проекта -------------------------------------------
# Скрипт лежит в tools/, а пакеты проекта (parser, collector, ...) — в корне.
# При запуске "python tools/check_parser.py" Python ищет модули только в
# tools/, поэтому добавляем корень проекта в sys.path вручную.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# -----------------------------------------------------------------------

from parser.ad_parser import parse_ad_structures, rebuild_decoded


def load_records(path: str) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def compare_field(name: str, expected, got) -> bool:
    if isinstance(expected, list):
        return sorted(expected) == sorted(got)
    return expected == got


def main() -> None:
    # путь к данным — относительно КОРНЯ, поэтому считаем его от ROOT,
    # а не от cwd: так скрипт найдёт capture.jsonl при запуске откуда угодно
    data_path = ROOT / "data" / "raw" / "capture.jsonl"
    if not data_path.exists():
        print("Файл не найден. Сначала запустите: python main.py")
        return

    records = load_records(str(data_path))
    print(f"Всего записей: {len(records)}")

    unique_payloads = {r["payload_hex"] for r in records}
    print(f"Уникальных payload_hex: {len(unique_payloads)}")

    # постраничный разбор первых 3 пакетов
    print("\n--- разбор AD-структур (первые 3 пакета) ---")
    for idx, r in enumerate(records[:3]):
        print(f"\nпакет #{idx}  address={r['address']}  payload_len={r['payload_length']}")
        try:
            structures = parse_ad_structures(r["payload_hex"])
        except ValueError as e:
            print(f"  ОШИБКА разбора: {e}")
            continue
        for s in structures:
            print(
                f"  offset={s['offset']:>2}  length={s['length']:>2}  "
                f"type=0x{s['type_code']:02X} ({s['type_name']})  "
                f"data={s['data_hex']}  decoded={s['decoded']}"
            )

    # сверка recovered vs эталон по всем пакетам
    print("\n--- сверка восстановленных полей с decoded симулятора ---")
    total_checks = 0
    mismatches = 0
    fields = ["local_name", "tx_power_dbm", "service_uuids", "manufacturer_data"]

    for idx, r in enumerate(records):
        try:
            structures = parse_ad_structures(r["payload_hex"])
        except ValueError as e:
            print(f"пакет #{idx}: MALFORMED ({e})")
            mismatches += len(fields)
            total_checks += len(fields)
            continue
        recovered = rebuild_decoded(structures)
        expected = r["decoded"]

        row = []
        for fld in fields:
            total_checks += 1
            ok = compare_field(fld, expected.get(fld), recovered.get(fld))
            if not ok:
                mismatches += 1
            row.append(f"{fld}={'OK' if ok else 'MISMATCH'}")
        if idx < 5:
            print(f"пакет #{idx:>3}:  " + "  ".join(row))

    print("\n--- итог ---")
    print(f"Сверок полей: {total_checks}, совпадений: {total_checks - mismatches}, "
          f"расхождений: {mismatches}")
    if mismatches == 0:
        print("Парсер восстанавливает структуру payload корректно.")
    else:
        print("ВНИМАНИЕ: есть расхождения, проверьте логику decode/rebuild.")


if __name__ == "__main__":
    main()