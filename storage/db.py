"""SQLite-хранилище: состояние, история, тревоги, доверенные профили."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "ble.db"

LEVEL_RANK = {"info": 0, "warning": 1, "alert": 2}
SUPPRESS_SEC = {"false_positive": 86400, "resolved": 3600}

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  signature TEXT PRIMARY KEY,
  name TEXT, vendor TEXT,
  first_seen REAL, last_seen REAL,
  packet_count INTEGER, duplicate_count INTEGER, unique_macs INTEGER,
  rssi_mean REAL, rssi_min REAL, rssi_max REAL, interval_mean REAL,
  baseline_frozen INTEGER, address_types TEXT
);

CREATE TABLE IF NOT EXISTS device_macs(
  signature TEXT, mac TEXT,
  first_seen REAL, last_seen REAL, count INTEGER,
  PRIMARY KEY(signature, mac)
);

CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  signature TEXT, ts REAL, reason TEXT,
  rssi REAL, packet_count INTEGER, unique_macs INTEGER
);
CREATE INDEX IF NOT EXISTS idx_obs ON observations(signature, ts);

CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  signature TEXT, device TEXT, types_key TEXT,
  level TEXT, score REAL,
  reasons_json TEXT, context_json TEXT,
  status TEXT DEFAULT 'new',
  created_at REAL, updated_at REAL, closed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts ON alerts(signature, types_key, status);

CREATE TABLE IF NOT EXISTS trusted_devices(
  signature TEXT PRIMARY KEY,
  expected_name TEXT, mfg_prefix TEXT,
  rssi_min REAL, rssi_max REAL,
  allow_payload_variation INTEGER DEFAULT 0,
  allow_mac_rotation INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  location TEXT, notes TEXT
);

CREATE TABLE IF NOT EXISTS captures(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT, started_at REAL, ended_at REAL, records INTEGER, note TEXT
);
"""


@contextmanager
def connect(path=None):
    """Отдельное соединение на каждую операцию — безопасно для потоков GUI."""
    p = Path(path) if path else DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(path=None):
    with connect(path) as c:
        c.executescript(SCHEMA)


# ---------- устройства ----------

def upsert_device(c, profile, vendor="Unknown"):
    r = profile.rssi_stats() or {}
    iv = profile.interval_stats() or {}
    name = (profile.stable_snapshot or {}).get("local_name")
    c.execute("""
        INSERT INTO devices(signature,name,vendor,first_seen,last_seen,
            packet_count,duplicate_count,unique_macs,
            rssi_mean,rssi_min,rssi_max,interval_mean,
            baseline_frozen,address_types)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(signature) DO UPDATE SET
            name=excluded.name, vendor=excluded.vendor,
            last_seen=excluded.last_seen,
            packet_count=excluded.packet_count,
            duplicate_count=excluded.duplicate_count,
            unique_macs=excluded.unique_macs,
            rssi_mean=excluded.rssi_mean, rssi_min=excluded.rssi_min,
            rssi_max=excluded.rssi_max, interval_mean=excluded.interval_mean,
            baseline_frozen=excluded.baseline_frozen,
            address_types=excluded.address_types
    """, (profile.signature, name, vendor, profile.first_seen, profile.last_seen,
          profile.packet_count, profile.duplicate_count, len(profile.mac_history),
          r.get("mean"), r.get("min"), r.get("max"), iv.get("mean"),
          int(profile.baseline_frozen),
          json.dumps(sorted(profile.address_types))))

    for m in profile.mac_history:
        c.execute("""
            INSERT INTO device_macs(signature,mac,first_seen,last_seen,count)
            VALUES(?,?,?,?,?)
            ON CONFLICT(signature,mac) DO UPDATE SET
                last_seen=excluded.last_seen, count=excluded.count
        """, (profile.signature, m["mac"], m["first_seen"], m["last_seen"], m["count"]))


def observe(c, profile, reason=None):
    """Пишет наблюдение только при значимом событии (иначе БД распухнет)."""
    prev = c.execute(
        "SELECT ts,rssi,unique_macs FROM observations "
        "WHERE signature=? ORDER BY ts DESC LIMIT 1",
        (profile.signature,)).fetchone()
    rssi = (profile.rssi_stats() or {}).get("mean")
    macs = len(profile.mac_history)
    ts = profile.last_seen

    if reason is None:
        if prev is None:
            reason = "first_seen"
        elif macs > prev["unique_macs"]:
            reason = "mac_change"
        elif rssi is not None and prev["rssi"] is not None and abs(rssi - prev["rssi"]) >= 10:
            reason = "rssi_jump"
        elif ts - prev["ts"] >= 60:
            reason = "heartbeat"
        else:
            return False

    c.execute("INSERT INTO observations(signature,ts,reason,rssi,packet_count,unique_macs)"
              " VALUES(?,?,?,?,?,?)",
              (profile.signature, ts, reason, rssi, profile.packet_count, macs))
    return True


# ---------- тревоги ----------

def upsert_alert(c, d, now=None):
    now = now or d.get("last_seen") or time.time()
    key = "|".join(sorted(d["cyber_types"] + d["physical_types"]))

    active = c.execute(
        "SELECT id FROM alerts WHERE signature=? AND types_key=? "
        "AND status IN ('new','acknowledged') ORDER BY id DESC LIMIT 1",
        (d["signature"], key)).fetchone()
    if active:
        c.execute("UPDATE alerts SET level=?,score=?,reasons_json=?,context_json=?,"
                  "updated_at=? WHERE id=?",
                  (d["level"], d["score"], json.dumps(d["reasons"], ensure_ascii=False),
                   json.dumps(d.get("context", {}), ensure_ascii=False), now, active["id"]))
        return active["id"]

    prev = c.execute(
        "SELECT status,closed_at,level FROM alerts WHERE signature=? AND types_key=? "
        "AND status IN ('resolved','false_positive') ORDER BY closed_at DESC LIMIT 1",
        (d["signature"], key)).fetchone()
    if prev and prev["closed_at"]:
        escalated = LEVEL_RANK[d["level"]] > LEVEL_RANK.get(prev["level"], 0)
        window = SUPPRESS_SEC.get(prev["status"], 3600)
        if not escalated and now - prev["closed_at"] < window:
            return None   # подавление повтора, но эскалация всегда проходит

    cur = c.execute(
        "INSERT INTO alerts(signature,device,types_key,level,score,reasons_json,"
        "context_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'new',?,?)",
        (d["signature"], d["device"], key, d["level"], d["score"],
         json.dumps(d["reasons"], ensure_ascii=False),
         json.dumps(d.get("context", {}), ensure_ascii=False), now, now))
    return cur.lastrowid


def set_status(c, alert_id, status):
    closed = time.time() if status in ("resolved", "false_positive") else None
    c.execute("UPDATE alerts SET status=?,closed_at=?,updated_at=? WHERE id=?",
              (status, closed, time.time(), alert_id))


def auto_resolve(c, signature):
    """Аномалия исчезла — закрываем активные тревоги сами."""
    c.execute("UPDATE alerts SET status='resolved',closed_at=?,updated_at=? "
              "WHERE signature=? AND status IN ('new','acknowledged')",
              (time.time(), time.time(), signature))


def list_alerts(c, status=None, limit=200):
    q = "SELECT * FROM alerts"
    args = []
    if status:
        q += " WHERE status=?"
        args.append(status)
    q += " ORDER BY updated_at DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in c.execute(q, args)]


def list_devices(c):
    return [dict(r) for r in c.execute("SELECT * FROM devices ORDER BY packet_count DESC")]


def history(c, signature, limit=500):
    return [dict(r) for r in c.execute(
        "SELECT ts,rssi,reason FROM observations WHERE signature=? ORDER BY ts LIMIT ?",
        (signature, limit))]


# ---------- доверенные ----------

def add_trusted(c, signature, name=None, rssi_min=-95, rssi_max=-30,
                allow_payload_variation=0, allow_mac_rotation=0,
                location="", notes=""):
    c.execute("""INSERT INTO trusted_devices(signature,expected_name,rssi_min,rssi_max,
        allow_payload_variation,allow_mac_rotation,location,notes)
        VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(signature) DO UPDATE SET
            expected_name=excluded.expected_name,
            rssi_min=excluded.rssi_min, rssi_max=excluded.rssi_max,
            allow_payload_variation=excluded.allow_payload_variation,
            allow_mac_rotation=excluded.allow_mac_rotation,
            location=excluded.location, notes=excluded.notes""",
        (signature, name, rssi_min, rssi_max,
         allow_payload_variation, allow_mac_rotation, location, notes))


def get_trusted(c, signature):
    r = c.execute("SELECT * FROM trusted_devices WHERE signature=? AND enabled=1",
                  (signature,)).fetchone()
    return dict(r) if r else None


def purge_old(c, days=7):
    """Историю чистим, тревоги храним всегда."""
    c.execute("DELETE FROM observations WHERE ts < ?",
              (time.time() - days * 86400,))