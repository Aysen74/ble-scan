"""
Точка входа проекта ble_privacy_tool.

На шаге 2 запускаем только симулятор легитимного устройства,
чтобы получить первый файл data/raw/capture.jsonl.
Позже сюда добавим реальный сборщик (bleak), профили,
анализаторы и корреляционный движок.
"""

from collector.simulator import simulate_device


def main() -> None:
    output = "data/raw/capture.jsonl"

    print(f"Генерирую легитимный BLE-трафик в {output} ...")
    n = simulate_device(
        output_path=output,
        name="TestSensor",
        base_rssi=-62.0,
        adv_interval=0.100,
        duration_sec=20,
    )
    print(f"Готово. Записано пакетов: {n}")


if __name__ == "__main__":
    main()
