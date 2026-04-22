"""
GhostNet Database Layer v4.0
SQLite persistence supporting Forensic Timelines, Memory Engines, and Aura 2.0.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Optional


DB_PATH = os.path.expanduser("~/.ghostnet/ghostnet_v4.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ssid        TEXT NOT NULL,
    bssid_hash  TEXT,
    encryption  TEXT,
    channel     INTEGER,
    signal      INTEGER,
    rssi        INTEGER,
    vendor      TEXT,
    risk        TEXT,
    risk_score  REAL,
    confidence  INTEGER,
    hidden      INTEGER DEFAULT 0,
    seen_at     TEXT NOT NULL,
    metadata    TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_hash    TEXT NOT NULL,
    ip          TEXT,
    vendor      TEXT,
    network_ssid TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    status      TEXT DEFAULT 'active',
    appearance_frequency INTEGER DEFAULT 1,
    trust_score INTEGER DEFAULT 50,
    active_duration_minutes INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    network     TEXT,
    ssid        TEXT,
    created_at  TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    reasoning   TEXT,
    factors     TEXT,
    confidence  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS forensic_timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    event_type  TEXT,
    description TEXT,
    related_mac TEXT,
    related_ssid TEXT
);

CREATE TABLE IF NOT EXISTS network_clusters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid_hash  TEXT,
    mac_hash    TEXT,
    connection_count INTEGER DEFAULT 1,
    last_connected TEXT
);

CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    date        TEXT NOT NULL,
    aura_score  INTEGER,
    network_count INTEGER,
    device_count  INTEGER,
    high_risk_count INTEGER,
    risk_volatility INTEGER DEFAULT 0,
    device_stability INTEGER DEFAULT 100
);

CREATE INDEX IF NOT EXISTS idx_networks_seen ON networks(seen_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_timeline_ts ON forensic_timeline(timestamp);
"""


class GhostDB:
    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    # ── NETWORKS ────────────────────────────────
    def store_networks(self, networks: List[dict]):
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            for net in networks:
                conn.execute(
                    """INSERT INTO networks
                       (ssid, encryption, channel, signal, rssi, vendor,
                        risk, risk_score, confidence, hidden, seen_at, metadata)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        net.get("ssid", ""),
                        net.get("encryption", ""),
                        net.get("channel", 0),
                        net.get("signal", 0),
                        net.get("rssi", 0),
                        net.get("vendor", "Unknown"),
                        net.get("risk", "low"),
                        net.get("risk_score", 0.0),
                        net.get("confidence", 0),
                        1 if net.get("hidden") else 0,
                        now,
                        json.dumps(net.get("metadata", {})),
                    )
                )

    def get_recent_networks(self, limit: int = 50) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT DISTINCT ssid, encryption, channel, signal, rssi,
                          vendor, risk, risk_score, confidence, hidden,
                          MAX(seen_at) as seen_at
                   FROM networks
                   GROUP BY ssid
                   ORDER BY seen_at DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── DEVICES & PROFILING ─────────────────────
    def store_device(self, device):
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id, appearance_frequency, active_duration_minutes FROM devices WHERE mac_hash = ?",
                (device.mac_hash,)
            ).fetchone()
            if existing:
                freq = existing["appearance_frequency"] + 1
                conn.execute(
                    "UPDATE devices SET last_seen=?, status=?, appearance_frequency=? WHERE mac_hash=?",
                    (now, device.status, freq, device.mac_hash)
                )
            else:
                conn.execute(
                    """INSERT INTO devices (mac_hash, ip, vendor, network_ssid, first_seen, last_seen, status, trust_score)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (device.mac_hash, getattr(device, 'ip', ''), device.vendor,
                     getattr(device, 'network_ssid', ''), now, now, device.status, getattr(device, 'trust_score', 50))
                )

    def get_recent_devices(self, limit: int = 30) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_device_profile(self, mac_hash: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM devices WHERE mac_hash=?", (mac_hash,)).fetchone()
            return dict(row) if row else None

    # ── FORENSIC TIMELINE ───────────────────────
    def log_event(self, event_type: str, description: str, related_mac: str = "", related_ssid: str = ""):
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO forensic_timeline (timestamp, event_type, description, related_mac, related_ssid) VALUES (?,?,?,?,?)",
                (now, event_type, description, related_mac, related_ssid)
            )

    def get_timeline(self, limit: int = 50) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM forensic_timeline ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ── ALERTS (EXPLAINABLE) ────────────────────
    def add_alert(self, severity: str, message: str, network: str = "", reasoning: str = "", factors: str = "", confidence: int = 0):
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO alerts (severity, message, network, ssid, created_at, reasoning, factors, confidence) VALUES (?,?,?,?,?,?,?,?)",
                (severity, message, network, network, now, reasoning, factors, confidence)
            )

    def get_alerts(self, limit: int = 50, unacknowledged_only: bool = False) -> List[dict]:
        with self._conn() as conn:
            q = "SELECT * FROM alerts"
            if unacknowledged_only:
                q += " WHERE acknowledged=0"
            q += " ORDER BY created_at DESC LIMIT ?"
            rows = conn.execute(q, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        with self._conn() as conn:
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    # ── AURA 2.0 ────────────────────────────────
    def store_aura(self, score: int, network_count: int, device_count: int, high_risk: int, volatility: int = 0, stability: int = 100):
        today = datetime.utcnow().date().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO baselines (date, aura_score, network_count, device_count, high_risk_count, risk_volatility, device_stability)
                   VALUES (?,?,?,?,?,?,?)""",
                (today, score, network_count, device_count, high_risk, volatility, stability)
            )

    def get_aura_history(self, days: int = 7) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM baselines ORDER BY date DESC LIMIT ?", (days,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── STATS ────────────────────────────────────
    def stats(self) -> dict:
        with self._conn() as conn:
            net_count = conn.execute("SELECT COUNT(DISTINCT ssid) FROM networks").fetchone()[0]
            dev_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
            event_count = conn.execute("SELECT COUNT(*) FROM forensic_timeline").fetchone()[0]
        return {
            "networks": net_count,
            "devices": dev_count,
            "active_alerts": alert_count,
            "events": event_count,
        }
