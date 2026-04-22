"""
GhostNet Behavioral Baseline Engine
Learns what's "normal" for your environment and flags deviations.

Tracks:
- Typical networks present at each hour-of-day
- Normal device count ranges
- Expected signal strength distributions
- Device churn rates (new/leaving devices per hour)
- Vendor mix patterns
"""

import json
import math
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


DB_PATH = os.path.expanduser("~/.ghostnet/ghostnet.db")

BASELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline_hourly (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hour        INTEGER NOT NULL,         -- 0-23
    dow         INTEGER NOT NULL,         -- 0=Mon, 6=Sun
    ssid        TEXT NOT NULL,
    appearances INTEGER DEFAULT 1,
    avg_signal  REAL DEFAULT 0,
    avg_rssi    REAL DEFAULT 0,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_device_churn (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hour            INTEGER NOT NULL,
    dow             INTEGER NOT NULL,
    avg_new_devices REAL DEFAULT 0,
    avg_lost_devices REAL DEFAULT 0,
    samples         INTEGER DEFAULT 0,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anomaly_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    anomaly_type    TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    delta_score     REAL DEFAULT 0,
    data            TEXT,
    detected_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_baseline_hour ON baseline_hourly(hour, dow);
"""


class BaselineEngine:
    """
    Learns normal network patterns over time and detects anomalies.

    After ~7 days of data, the baseline becomes reliable.
    The engine produces an "anomaly delta" that feeds into the Aura Score.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript(BASELINE_SCHEMA)

    # ── LEARNING ────────────────────────────────────
    def learn(self, networks: List[dict], devices: List[dict]):
        """
        Update the baseline model with a new observation.
        Call this after every scan.
        """
        now = datetime.now()
        hour = now.hour
        dow = now.weekday()
        ts = now.isoformat()

        with self._conn() as conn:
            for net in networks:
                ssid = net.get("ssid", "")
                if not ssid:
                    continue
                existing = conn.execute(
                    "SELECT id, appearances, avg_signal, avg_rssi FROM baseline_hourly WHERE hour=? AND dow=? AND ssid=?",
                    (hour, dow, ssid)
                ).fetchone()

                sig = net.get("signal", 2)
                rssi = net.get("rssi", -70)

                if existing:
                    n = existing["appearances"]
                    new_sig = (existing["avg_signal"] * n + sig) / (n + 1)
                    new_rssi = (existing["avg_rssi"] * n + rssi) / (n + 1)
                    conn.execute(
                        "UPDATE baseline_hourly SET appearances=?, avg_signal=?, avg_rssi=?, updated_at=? WHERE id=?",
                        (n + 1, new_sig, new_rssi, ts, existing["id"])
                    )
                else:
                    conn.execute(
                        "INSERT INTO baseline_hourly (hour, dow, ssid, appearances, avg_signal, avg_rssi, updated_at) VALUES (?,?,?,1,?,?,?)",
                        (hour, dow, ssid, sig, rssi, ts)
                    )

    # ── ANOMALY DETECTION ────────────────────────────
    def detect_anomalies(self, networks: List[dict]) -> List[dict]:
        """
        Compare current observations against baseline.
        Returns list of anomaly dicts with severity and description.
        """
        now = datetime.now()
        hour = now.hour
        dow = now.weekday()
        anomalies = []

        with self._conn() as conn:
            # Load known networks for this time slot
            known = conn.execute(
                "SELECT ssid, avg_signal, avg_rssi, appearances FROM baseline_hourly WHERE hour=? AND dow=?",
                (hour, dow)
            ).fetchall()
            known_map = {row["ssid"]: dict(row) for row in known}

        current_ssids = {n.get("ssid", "") for n in networks if n.get("ssid")}
        known_ssids = set(known_map.keys())

        # 1. New networks not seen at this time before
        new_nets = current_ssids - known_ssids
        for ssid in new_nets:
            net = next((n for n in networks if n.get("ssid") == ssid), {})
            severity = "high" if net.get("encryption") == "OPEN" else "medium"
            anomalies.append({
                "type": "new_network",
                "ssid": ssid,
                "severity": severity,
                "description": f"Network '{ssid}' not seen at this time previously",
                "delta": -8 if severity == "high" else -3,
            })

        # 2. Networks that disappeared unexpectedly (only flag if seen many times)
        missing = known_ssids - current_ssids
        for ssid in missing:
            info = known_map[ssid]
            if info["appearances"] >= 5:  # Only flag reliable networks
                anomalies.append({
                    "type": "missing_network",
                    "ssid": ssid,
                    "severity": "low",
                    "description": f"Regular network '{ssid}' not detected",
                    "delta": -1,
                })

        # 3. Signal anomalies vs baseline
        for net in networks:
            ssid = net.get("ssid", "")
            if ssid in known_map:
                expected_rssi = known_map[ssid]["avg_rssi"]
                actual_rssi = net.get("rssi", -70)
                delta_rssi = actual_rssi - expected_rssi  # positive = stronger than normal

                if delta_rssi > 15:  # Suspiciously stronger
                    anomalies.append({
                        "type": "signal_spike",
                        "ssid": ssid,
                        "severity": "medium",
                        "description": f"'{ssid}' is {delta_rssi:.0f}dBm stronger than baseline — possible repositioning",
                        "delta": -5,
                    })
                elif delta_rssi < -20:  # Much weaker
                    anomalies.append({
                        "type": "signal_drop",
                        "ssid": ssid,
                        "severity": "low",
                        "description": f"'{ssid}' signal dropped {abs(delta_rssi):.0f}dBm below baseline",
                        "delta": -1,
                    })

        # Log anomalies to DB
        self._log_anomalies(anomalies)
        return anomalies

    def _log_anomalies(self, anomalies: List[dict]):
        if not anomalies:
            return
        now = datetime.now().isoformat()
        with self._conn() as conn:
            for a in anomalies:
                conn.execute(
                    "INSERT INTO anomaly_log (anomaly_type, description, severity, delta_score, detected_at) VALUES (?,?,?,?,?)",
                    (a.get("type", ""), a.get("description", ""), a.get("severity", "low"), a.get("delta", 0), now)
                )

    def get_recent_anomalies(self, limit: int = 20) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM anomaly_log ORDER BY detected_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def baseline_age_days(self) -> float:
        """How many days of baseline data we have."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MIN(updated_at) as oldest FROM baseline_hourly"
            ).fetchone()
            if not row or not row["oldest"]:
                return 0.0
            oldest = datetime.fromisoformat(row["oldest"])
            return (datetime.now() - oldest).total_seconds() / 86400

    def confidence_pct(self) -> int:
        """Baseline confidence as a percentage (100% after 14 days of data)."""
        days = self.baseline_age_days()
        return min(100, int(days / 14 * 100))
