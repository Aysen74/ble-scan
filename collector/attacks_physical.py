"""
Сценарии для валидации физического анализатора.

Используют виртуальное время (без sleep) и фиксированное зерно ГСЧ,
поэтому воспроизводимы и генерируются мгновенно. Формат записей
совпадает с collector.simulator, остальной конвейер не меняется.

Сценарии:
  legit_two_phase   — две фазы одного легитимного устройства (ожидаем 0);
  clone_rssi_shift  — клон: тот же MAC и payload, RSSI сдвинут на +18 дБ;
  replay_no_jitter  — программная генерация: джиттер исчезает;
  tx_power_spoof    — заявленная мощность меняется при стабильном RSSI.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from collector.simulator import (
    build_adv_payload,
    build_event_record,
    generate_random_static_mac,
    uuid16_to_full,
)


def _phase(f, mac, name, mfg_id, mfg_hex, uuid16, tx, t, n,
           interval, jitter, rssi_mean, rssi_sigma, source):
    payload_hex = build_adv_payload(
        name=name, tx_power_dbm=tx, uuids_16=[uuid16],
        manufacturer_id=mfg_id, manufacturer_data=bytes.fromhex(mfg_hex),
    ).hex()
    decoded = {
        "local_name": name,
        "tx_power_dbm": tx,
        "service_uuids": [uuid16_to_full(int(uuid16, 16))],
        "manufacturer_data": {f"0x{mfg_id:04X}": mfg_hex},
    }
    for _ in range(n):
        rec = build_event_record(
            timestamp_unix=t, address=mac, address_type="random",
            rssi_dbm=random.gauss(rssi_mean, rssi_sigma),
            channel=random.choice([37, 38, 39]),
            payload_hex=payload_hex, decoded=decoded, source=source,
        )
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        t += interval + (random.uniform(-jitter, jitter) if jitter else 0.0)
    return t


def _run(path, phases, seed=42):
    random.seed(seed)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    mac = generate_random_static_mac()
    t = time.time()
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for ph in phases:
            t = _phase(f, mac, t=t, **ph)
            count += ph["n"]
    return count


def scenario_legit_two_phase(path, n1=80, n2=80):
    common = dict(name="PhysSensor", mfg_id=0x004C, mfg_hex="a1b2c3",
                  uuid16="0x180D", tx=0, interval=0.100, jitter=0.020,
                  rssi_mean=-62.0, rssi_sigma=2.5, source="legit")
    return _run(path, [dict(common, n=n1), dict(common, n=n2)])


def scenario_clone_rssi_shift(path, n1=80, n2=80):
    base = dict(name="PhysSensor", mfg_id=0x004C, mfg_hex="a1b2c3",
                uuid16="0x180D", tx=0, interval=0.100, jitter=0.020,
                rssi_sigma=2.5)
    return _run(path, [
        dict(base, n=n1, rssi_mean=-62.0, source="legit"),
        dict(base, n=n2, rssi_mean=-44.0, source="attack_clone_rssi"),
    ])


def scenario_replay_no_jitter(path, n1=80, n2=80):
    base = dict(name="PhysSensor", mfg_id=0x004C, mfg_hex="a1b2c3",
                uuid16="0x180D", tx=0, interval=0.100,
                rssi_mean=-62.0, rssi_sigma=2.5)
    return _run(path, [
        dict(base, n=n1, jitter=0.020, source="legit"),
        dict(base, n=n2, jitter=0.0, source="attack_replay"),
    ])


def scenario_tx_power_spoof(path, n1=80, n2=80):
    base = dict(name="PhysSensor", mfg_id=0x004C, mfg_hex="a1b2c3",
                uuid16="0x180D", interval=0.100, jitter=0.020,
                rssi_mean=-62.0, rssi_sigma=2.5)
    return _run(path, [
        dict(base, n=n1, tx=0, source="legit"),
        dict(base, n=n2, tx=12, source="attack_tx_spoof"),
    ])

def scenario_clone_combined(path, n1=80, n2=80):
    """Клон: и сигнал сильнее, и вещание чаще нормы BLE."""
    base = dict(name="PhysSensor", mfg_id=0x004C, mfg_hex="a1b2c3",
                uuid16="0x180D", tx=0, rssi_sigma=2.5)
    return _run(path, [
        dict(base, n=n1, interval=0.100, jitter=0.020,
             rssi_mean=-62.0, source="legit"),
        dict(base, n=n2, interval=0.012, jitter=0.001,
             rssi_mean=-44.0, source="attack_clone_combined"),
    ])