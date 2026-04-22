"""
GhostNet Risk Engine
Multi-factor network risk scoring with behavioral analysis and confidence scoring.
"""

import math
from typing import List, Optional


class RiskEngine:
    """
    Scores networks across multiple risk dimensions:
    - Encryption type (WPA3=safe, OPEN=danger)
    - SSID patterns (known honeypot names, suspicious patterns)
    - Signal anomalies (too strong = suspicious proximity)
    - Device churn rate
    - Vendor mismatch
    - Behavioral baseline delta
    """

    HONEYPOT_PATTERNS = [
        "free", "wifi", "open", "guest", "public", "internet",
        "$$", "!!!", "....", "hotel", "airport", "starbucks"
    ]
    SUSPICIOUS_SSID_PATTERNS = [
        r"^\$\$",          # starts with $$
        r"^!{2,}",         # multiple !
        r"[^\x20-\x7E]",   # non-printable chars
    ]
    KNOWN_SAFE_VENDORS = {"cisco", "netgear", "tp-link", "asus", "aruba", "ubiquiti"}
    KNOWN_RISKY_VENDORS = {"unknown", ""}

    WEIGHTS = {
        "encryption":       0.35,
        "ssid_pattern":     0.20,
        "signal_anomaly":   0.15,
        "vendor_trust":     0.10,
        "device_churn":     0.10,
        "hidden_ssid":      0.10,
    }

    ENC_SCORES = {
        "WPA3": 0.0,
        "WPA2": 0.2,
        "WPA":  0.5,
        "WEP":  0.9,
        "OPEN": 1.0,
    }

    def score_networks(self, networks: List[dict]) -> List[dict]:
        """Score and annotate each network with risk level and confidence."""
        scored = []
        for net in networks:
            result = self._score_one(net)
            net.update(result)
            scored.append(net)
        # Sort: high risk first
        return sorted(scored, key=lambda n: {"high": 0, "medium": 1, "low": 2}.get(n["risk"], 3))

    def _score_one(self, net: dict) -> dict:
        enc = net.get("encryption", "OPEN")
        ssid = net.get("ssid", "").lower()
        rssi = net.get("rssi", -70)
        vendor = net.get("vendor", "Unknown").lower()
        hidden = net.get("hidden", ssid == "" or ssid == "[hidden]")

        factors = {}

        # 1. Encryption score
        factors["encryption"] = self.ENC_SCORES.get(enc, 0.5)

        # 2. SSID pattern risk
        ssid_risk = 0.0
        if ssid.startswith("$$") or ssid.startswith("!!!"):
            ssid_risk = 1.0
        elif any(p in ssid for p in self.HONEYPOT_PATTERNS) and enc == "OPEN":
            ssid_risk = 0.8
        elif len(ssid) > 30:
            ssid_risk = 0.3
        elif ssid == "linksys" or ssid == "netgear" or ssid == "dlink":
            ssid_risk = 0.5  # Default SSIDs = unconfigured/forgotten router
        factors["ssid_pattern"] = ssid_risk

        # 3. Signal anomaly — very strong signal from unknown = proximity attack
        if rssi > -45 and vendor in self.KNOWN_RISKY_VENDORS:
            factors["signal_anomaly"] = 0.9
        elif rssi > -50 and enc == "OPEN":
            factors["signal_anomaly"] = 0.7
        else:
            factors["signal_anomaly"] = 0.0

        # 4. Vendor trust
        if vendor in self.KNOWN_SAFE_VENDORS:
            factors["vendor_trust"] = 0.0
        elif vendor in self.KNOWN_RISKY_VENDORS:
            factors["vendor_trust"] = 0.7
        else:
            factors["vendor_trust"] = 0.3

        # 5. Device churn (simulated; in production read from DB)
        factors["device_churn"] = 0.2  # placeholder

        # 6. Hidden SSID
        factors["hidden_ssid"] = 0.6 if hidden else 0.0

        # Weighted score
        raw_score = sum(factors[k] * self.WEIGHTS[k] for k in factors)
        raw_score = max(0.0, min(1.0, raw_score))

        # Hard override: OPEN network is always at least high
        if enc == "OPEN":
            risk = "high"
        elif raw_score >= 0.55:
            risk = "high"
        elif raw_score >= 0.28:
            risk = "medium"
        else:
            risk = "low"

        # Confidence — higher when multiple high-scoring factors agree
        factor_vals = list(factors.values())
        variance = sum((v - raw_score) ** 2 for v in factor_vals) / len(factor_vals)
        # Boost confidence when encryption is OPEN (clear-cut case)
        if enc == "OPEN":
            confidence = int(max(80, min(99, 99 - variance * 100)))
        else:
            confidence = int(max(50, min(99, 99 - variance * 200)))

        return {
            "risk": risk,
            "risk_score": round(raw_score, 3),
            "confidence": confidence,
            "risk_factors": factors,
        }

    def compute_aura_score(self, networks: List[dict], devices: List[dict]) -> int:
        """
        Compute the Digital Aura Score (0-100).
        Higher = safer environment.
        """
        if not networks:
            return 80  # No data = unknown, neutral

        high_risk = sum(1 for n in networks if n.get("risk") == "high")
        medium_risk = sum(1 for n in networks if n.get("risk") == "medium")
        open_nets = sum(1 for n in networks if n.get("encryption") == "OPEN")
        unknown_devs = sum(1 for d in devices if d.get("vendor", "").lower() in ("", "unknown"))

        total = len(networks)
        score = 100
        score -= (high_risk / total) * 40
        score -= (medium_risk / total) * 20
        score -= (open_nets / total) * 15
        score -= (unknown_devs / max(len(devices), 1)) * 10

        return max(0, min(100, int(score)))
