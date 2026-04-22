"""
GhostNet Digital Aura Score Engine
Computes a holistic 0-100 environment safety score across multiple dimensions.

The Aura Score is the core UX concept of GhostNet — a single number that tells
you how safe your current network environment is. It combines:

  - Network risk profile (40%)
  - Behavioral anomalies (25%)
  - Device environment (15%)
  - Encryption quality (20%)
"""

from typing import List, Optional
from dataclasses import dataclass


@dataclass
class AuraComponents:
    network_score: float       # 0-100: based on risk levels
    anomaly_score: float       # 0-100: based on detected anomalies
    device_score: float        # 0-100: based on known/unknown devices
    encryption_score: float    # 0-100: WPA3=100, OPEN=0
    baseline_confidence: int   # 0-100: how mature the baseline is

    WEIGHTS = {
        "network": 0.40,
        "anomaly": 0.25,
        "encryption": 0.20,
        "device": 0.15,
    }

    def total(self) -> int:
        raw = (
            self.network_score    * self.WEIGHTS["network"] +
            self.anomaly_score    * self.WEIGHTS["anomaly"] +
            self.encryption_score * self.WEIGHTS["encryption"] +
            self.device_score     * self.WEIGHTS["device"]
        )
        return max(0, min(100, int(raw)))

    def label(self) -> str:
        t = self.total()
        if t >= 85:  return "EXCELLENT"
        if t >= 70:  return "GOOD"
        if t >= 50:  return "CAUTION"
        if t >= 30:  return "DANGER"
        return "CRITICAL"

    def label_color(self) -> str:
        t = self.total()
        if t >= 85:  return "bright_green"
        if t >= 70:  return "green"
        if t >= 50:  return "yellow"
        if t >= 30:  return "red"
        return "bold red"

    def recommendations(self) -> List[str]:
        recs = []
        t = self.total()
        if self.encryption_score < 60:
            recs.append("Multiple open or weak-encryption networks detected — enable VPN")
        if self.anomaly_score < 60:
            recs.append("Behavioral anomalies above threshold — review recent alerts")
        if self.device_score < 50:
            recs.append("High proportion of unknown devices — switch to PARANOID mode")
        if self.network_score < 50:
            recs.append("Several high-risk networks in range — avoid public WiFi")
        if self.baseline_confidence < 30:
            recs.append("Baseline model immature — run GhostNet daily to improve accuracy")
        if not recs:
            recs.append("Environment looks safe — maintain BALANCED alert mode")
        return recs


class AuraEngine:
    """Computes and tracks the Digital Aura Score."""

    ENC_SCORES = {
        "WPA3": 100,
        "WPA2": 70,
        "WPA":  40,
        "WEP":  10,
        "OPEN": 0,
    }

    def compute(
        self,
        networks: List[dict],
        devices: List[dict],
        anomalies: List[dict],
        baseline_confidence: int = 0,
    ) -> AuraComponents:

        return AuraComponents(
            network_score=self._network_score(networks),
            anomaly_score=self._anomaly_score(anomalies),
            device_score=self._device_score(devices),
            encryption_score=self._encryption_score(networks),
            baseline_confidence=baseline_confidence,
        )

    def _network_score(self, networks: List[dict]) -> float:
        if not networks:
            return 75.0  # No data — neutral
        penalty = 0.0
        for n in networks:
            risk = n.get("risk", "low")
            conf = n.get("confidence", 50) / 100
            if risk == "high":
                penalty += 25 * conf
            elif risk == "medium":
                penalty += 10 * conf
        return max(0.0, 100.0 - penalty)

    def _anomaly_score(self, anomalies: List[dict]) -> float:
        if not anomalies:
            return 100.0
        total_delta = sum(abs(a.get("delta", 0)) for a in anomalies)
        return max(0.0, 100.0 - total_delta * 3)

    def _device_score(self, devices: List[dict]) -> float:
        if not devices:
            return 80.0
        unknown = sum(1 for d in devices if d.get("vendor", "").lower() in ("", "unknown"))
        ratio = unknown / len(devices)
        return max(0.0, 100.0 - ratio * 60)

    def _encryption_score(self, networks: List[dict]) -> float:
        if not networks:
            return 70.0
        scores = [self.ENC_SCORES.get(n.get("encryption", "WPA2"), 50) for n in networks]
        return sum(scores) / len(scores)

    def delta_from_baseline(self, current: int, baseline: int) -> str:
        diff = current - baseline
        if diff > 0:
            return f"[bright_green]↑ +{diff}[/bright_green]"
        elif diff < 0:
            return f"[red]↓ {diff}[/red]"
        return "[dim green]→ unchanged[/dim green]"
