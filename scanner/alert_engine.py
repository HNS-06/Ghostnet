"""
GhostNet Alert System
Real-time trigger system with three adaptive modes:
  - CHILL:    Only flag high-risk events (open networks, clear attacks)
  - BALANCED: Flag high + medium + new unknown devices (default)
  - PARANOID: Flag everything including signal variations and new SSIDs
"""

import os
import time
import threading
from datetime import datetime
from typing import List, Callable, Optional
from dataclasses import dataclass, field


@dataclass
class Alert:
    severity: str              # high / medium / low / info
    title: str
    message: str
    network: str = ""
    ssid: str = ""
    timestamp: str = ""
    acknowledged: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def icon(self) -> str:
        return {"high": "⚠", "medium": "◬", "low": "●", "info": "◈"}.get(self.severity, "◈")

    @property
    def color(self) -> str:
        return {"high": "bold red", "medium": "yellow", "low": "green", "info": "cyan"}.get(self.severity, "green")


class AlertMode:
    CHILL    = "chill"
    BALANCED = "balanced"
    PARANOID = "paranoid"

    # Minimum risk level to trigger an alert per mode
    THRESHOLDS = {
        "chill":    {"high"},
        "balanced": {"high", "medium"},
        "paranoid": {"high", "medium", "low"},
    }

    @staticmethod
    def should_alert(mode: str, severity: str) -> bool:
        return severity in AlertMode.THRESHOLDS.get(mode, {"high"})


class AlertRule:
    """Defines a condition that triggers an alert."""

    def __init__(self, rule_id: str, name: str, mode_threshold: str, check_fn: Callable, severity: str):
        self.rule_id = rule_id
        self.name = name
        self.mode_threshold = mode_threshold
        self.check_fn = check_fn  # (networks, devices, anomalies) -> Optional[Alert]
        self.severity = severity
        self._last_fired: float = 0
        self._cooldown_s: int = 300  # 5 min cooldown to avoid spam

    def evaluate(self, networks, devices, anomalies) -> Optional[Alert]:
        now = time.time()
        if now - self._last_fired < self._cooldown_s:
            return None
        result = self.check_fn(networks, devices, anomalies)
        if result:
            self._last_fired = now
        return result


class AlertEngine:
    """
    Evaluates alert rules against scan results and fires notifications.
    Supports callbacks for terminal display, sound, desktop notifications.
    """

    def __init__(self, mode: str = AlertMode.BALANCED):
        self.mode = mode
        self._callbacks: List[Callable[[Alert], None]] = []
        self._history: List[Alert] = []
        self._rules = self._build_default_rules()
        self._lock = threading.Lock()

    def set_mode(self, mode: str):
        if mode in (AlertMode.CHILL, AlertMode.BALANCED, AlertMode.PARANOID):
            self.mode = mode

    def on_alert(self, callback: Callable[[Alert], None]):
        """Register a callback to be called when an alert fires."""
        self._callbacks.append(callback)

    def evaluate(self, networks: List[dict], devices: List[dict], anomalies: List[dict]) -> List[Alert]:
        """Evaluate all rules and return fired alerts."""
        fired = []
        for rule in self._rules:
            if not AlertMode.should_alert(self.mode, rule.severity):
                continue
            alert = rule.evaluate(networks, devices, anomalies)
            if alert:
                fired.append(alert)
                with self._lock:
                    self._history.append(alert)
                for cb in self._callbacks:
                    try:
                        cb(alert)
                    except Exception:
                        pass
        return fired

    def get_history(self, limit: int = 50) -> List[Alert]:
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def _build_default_rules(self) -> List[AlertRule]:
        return [
            AlertRule(
                "open_network", "Open Network Detected",
                AlertMode.CHILL,
                lambda nets, devs, anoms: self._check_open_network(nets),
                "high"
            ),
            AlertRule(
                "honeypot_ssid", "Honeypot SSID Pattern",
                AlertMode.CHILL,
                lambda nets, devs, anoms: self._check_honeypot(nets),
                "high"
            ),
            AlertRule(
                "signal_spike", "Signal Spike (MITM Risk)",
                AlertMode.BALANCED,
                lambda nets, devs, anoms: self._check_signal_spike(anoms),
                "medium"
            ),
            AlertRule(
                "new_device", "Unknown Device Appeared",
                AlertMode.BALANCED,
                lambda nets, devs, anoms: self._check_new_device(devs),
                "medium"
            ),
            AlertRule(
                "hidden_ssid", "Hidden SSID Probe",
                AlertMode.BALANCED,
                lambda nets, devs, anoms: self._check_hidden_ssid(nets),
                "medium"
            ),
            AlertRule(
                "new_network", "New Network (Baseline Anomaly)",
                AlertMode.PARANOID,
                lambda nets, devs, anoms: self._check_new_network(anoms),
                "low"
            ),
            AlertRule(
                "device_churn", "High Device Churn",
                AlertMode.PARANOID,
                lambda nets, devs, anoms: self._check_device_churn(devs),
                "low"
            ),
        ]

    # ── RULE IMPLEMENTATIONS ────────────────────────
    def _check_open_network(self, networks: List[dict]) -> Optional[Alert]:
        open_nets = [n for n in networks if n.get("encryption") == "OPEN"]
        if open_nets:
            ssids = ", ".join(n.get("ssid", "?") for n in open_nets[:3])
            return Alert(
                severity="high",
                title="OPEN NETWORK DETECTED",
                message=f"Unencrypted network(s) in range: {ssids}. Risk of data interception.",
                ssid=open_nets[0].get("ssid", ""),
            )
        return None

    def _check_honeypot(self, networks: List[dict]) -> Optional[Alert]:
        patterns = ["$$", "!!!", "free_wifi", "freewifi", "internet_gratis"]
        for net in networks:
            ssid = net.get("ssid", "").lower()
            if any(p in ssid for p in patterns) and net.get("signal", 0) >= 3:
                return Alert(
                    severity="high",
                    title="HONEYPOT PATTERN DETECTED",
                    message=f"'{net.get('ssid')}' matches known rogue AP naming patterns. Strong signal ({net.get('rssi', 0)}dBm) suggests deliberate positioning.",
                    ssid=net.get("ssid", ""),
                )
        return None

    def _check_signal_spike(self, anomalies: List[dict]) -> Optional[Alert]:
        spikes = [a for a in anomalies if a.get("type") == "signal_spike"]
        if spikes:
            a = spikes[0]
            return Alert(
                severity="medium",
                title="SIGNAL ANOMALY DETECTED",
                message=a.get("description", "Unexpected signal spike"),
                ssid=a.get("ssid", ""),
            )
        return None

    def _check_new_device(self, devices: List[dict]) -> Optional[Alert]:
        new = [d for d in devices if d.get("status") == "new" or d.get("first_seen", "") == "just now"]
        unknown_new = [d for d in new if d.get("vendor", "").lower() in ("", "unknown")]
        if unknown_new:
            return Alert(
                severity="medium",
                title="UNKNOWN NEW DEVICE",
                message=f"Unidentified device joined network: {unknown_new[0].get('ip', '?')} — vendor fingerprint unknown.",
            )
        return None

    def _check_hidden_ssid(self, networks: List[dict]) -> Optional[Alert]:
        hidden = [n for n in networks if n.get("hidden") or n.get("ssid", "") in ("", "[HIDDEN]")]
        if hidden:
            return Alert(
                severity="medium",
                title="HIDDEN SSID DETECTED",
                message=f"{len(hidden)} hidden network(s) broadcasting on nearby channels. Passive probing in progress.",
            )
        return None

    def _check_new_network(self, anomalies: List[dict]) -> Optional[Alert]:
        new = [a for a in anomalies if a.get("type") == "new_network"]
        if new:
            return Alert(
                severity="low",
                title="BASELINE ANOMALY",
                message=f"Network '{new[0].get('ssid', '?')}' not seen at this time previously.",
                ssid=new[0].get("ssid", ""),
            )
        return None

    def _check_device_churn(self, devices: List[dict]) -> Optional[Alert]:
        # Simplified: flag if more than 10 devices seen (high churn indicator in public spaces)
        if len(devices) > 10:
            return Alert(
                severity="low",
                title="HIGH DEVICE DENSITY",
                message=f"{len(devices)} devices detected — elevated public environment risk.",
            )
        return None
