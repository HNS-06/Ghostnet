"""
GhostNet Test Suite
pytest tests for core modules.

Run: pytest tests/ -v
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── RISK ENGINE TESTS ────────────────────────────────────────
class TestRiskEngine:
    def setup_method(self):
        from scanner.risk_engine import RiskEngine
        self.engine = RiskEngine()

    def test_open_network_is_high_risk(self):
        net = {"ssid": "TestNet", "encryption": "OPEN", "signal": 3, "rssi": -60, "vendor": "Unknown"}
        result = self.engine._score_one(net)
        assert result["risk"] == "high"

    def test_wpa3_network_is_low_risk(self):
        net = {"ssid": "HomeWPA3", "encryption": "WPA3", "signal": 3, "rssi": -60, "vendor": "Cisco"}
        result = self.engine._score_one(net)
        assert result["risk"] == "low"

    def test_honeypot_ssid_elevates_risk(self):
        net = {"ssid": "$$FREE_WIFI$$", "encryption": "OPEN", "signal": 4, "rssi": -38, "vendor": "Unknown"}
        result = self.engine._score_one(net)
        assert result["risk"] == "high"
        assert result["confidence"] >= 80

    def test_confidence_is_in_range(self):
        net = {"ssid": "Test", "encryption": "WPA2", "signal": 2, "rssi": -70, "vendor": "TP-Link"}
        result = self.engine._score_one(net)
        assert 0 <= result["confidence"] <= 100

    def test_score_networks_sorted_high_first(self):
        networks = [
            {"ssid": "Safe", "encryption": "WPA3", "signal": 3, "rssi": -60, "vendor": "Cisco"},
            {"ssid": "Danger", "encryption": "OPEN", "signal": 4, "rssi": -40, "vendor": "Unknown"},
            {"ssid": "Middle", "encryption": "WPA2", "signal": 2, "rssi": -70, "vendor": "TP-Link"},
        ]
        scored = self.engine.score_networks(networks)
        assert scored[0]["risk"] == "high"

    def test_strong_signal_unknown_vendor_anomaly(self):
        net = {"ssid": "MysteryAP", "encryption": "OPEN", "signal": 4, "rssi": -35, "vendor": "Unknown"}
        result = self.engine._score_one(net)
        assert result["risk_factors"]["signal_anomaly"] > 0.5

    def test_aura_score_in_range(self):
        nets = [
            {"risk": "high", "encryption": "OPEN"},
            {"risk": "low", "encryption": "WPA3"},
        ]
        devs = [{"vendor": "Apple"}, {"vendor": "Unknown"}]
        score = self.engine.compute_aura_score(nets, devs)
        assert 0 <= score <= 100

    def test_aura_decreases_with_more_risk(self):
        safe_nets = [{"risk": "low", "encryption": "WPA3"}] * 5
        risky_nets = [{"risk": "high", "encryption": "OPEN"}] * 5
        devs = [{"vendor": "Apple"}]
        safe_score = self.engine.compute_aura_score(safe_nets, devs)
        risky_score = self.engine.compute_aura_score(risky_nets, devs)
        assert safe_score > risky_score


# ── AURA ENGINE TESTS ────────────────────────────────────────
class TestAuraEngine:
    def setup_method(self):
        from scanner.aura import AuraEngine
        self.engine = AuraEngine()

    def test_all_wpa3_max_encryption_score(self):
        nets = [{"encryption": "WPA3"}, {"encryption": "WPA3"}]
        score = self.engine._encryption_score(nets)
        assert score == 100.0

    def test_all_open_zero_encryption_score(self):
        nets = [{"encryption": "OPEN"}, {"encryption": "OPEN"}]
        score = self.engine._encryption_score(nets)
        assert score == 0.0

    def test_no_anomalies_full_score(self):
        score = self.engine._anomaly_score([])
        assert score == 100.0

    def test_aura_components_label(self):
        from scanner.aura import AuraComponents
        comp = AuraComponents(90, 90, 90, 90, 80)
        assert comp.label() == "EXCELLENT"
        comp2 = AuraComponents(10, 10, 10, 10, 20)
        assert comp2.label() in ("CRITICAL", "DANGER")

    def test_compute_returns_aura_components(self):
        from scanner.aura import AuraComponents
        nets = [{"risk": "low", "confidence": 90, "encryption": "WPA3"}]
        result = self.engine.compute(nets, [], [], baseline_confidence=50)
        assert isinstance(result, AuraComponents)
        assert 0 <= result.total() <= 100


# ── ALERT ENGINE TESTS ───────────────────────────────────────
class TestAlertEngine:
    def setup_method(self):
        from scanner.alert_engine import AlertEngine, AlertMode
        self.engine = AlertEngine(mode=AlertMode.BALANCED)

    def test_open_network_triggers_high_alert(self):
        nets = [{"ssid": "FreeWifi", "encryption": "OPEN", "signal": 3, "rssi": -55}]
        alerts = self.engine.evaluate(nets, [], [])
        sev = [a.severity for a in alerts]
        assert "high" in sev

    def test_chill_mode_ignores_medium(self):
        from scanner.alert_engine import AlertMode
        self.engine.set_mode(AlertMode.CHILL)
        # Only medium-severity events
        nets = [{"ssid": "Meh", "encryption": "WPA2", "signal": 2, "rssi": -70}]
        anomalies = [{"type": "signal_spike", "ssid": "Meh", "severity": "medium", "description": "spike", "delta": -5}]
        alerts = self.engine.evaluate(nets, [], anomalies)
        medium_alerts = [a for a in alerts if a.severity == "medium"]
        assert len(medium_alerts) == 0

    def test_alert_has_required_fields(self):
        nets = [{"ssid": "$$EVIL$$", "encryption": "OPEN", "signal": 4, "rssi": -40}]
        alerts = self.engine.evaluate(nets, [], [])
        if alerts:
            a = alerts[0]
            assert a.title
            assert a.message
            assert a.severity in ("high", "medium", "low", "info")
            assert a.timestamp

    def test_mode_change(self):
        from scanner.alert_engine import AlertMode
        self.engine.set_mode(AlertMode.PARANOID)
        assert self.engine.mode == AlertMode.PARANOID


# ── DEVICE FINGERPRINTER TESTS ───────────────────────────────
class TestFingerprinter:
    def setup_method(self):
        from scanner.fingerprint import DeviceFingerprinter
        self.fp = DeviceFingerprinter()

    def test_known_oui_resolved(self):
        result = self.fp.fingerprint("E4:B8:7C")
        assert result["vendor"] == "Samsung"

    def test_unknown_oui_flagged(self):
        result = self.fp.fingerprint("AA:BB:CC")
        assert result["is_unknown"] is True

    def test_gateway_ip_detected(self):
        result = self.fp.fingerprint("00:23:69", ip="192.168.1.1")
        assert result.get("likely_gateway") is True

    def test_apipa_ip_detected(self):
        result = self.fp.fingerprint("00:00:00", ip="169.254.1.100")
        assert result.get("apipa") is True

    def test_environment_classification(self):
        devices = [
            {"device_class": "🌐 Infrastructure", "is_unknown": False},
            {"device_class": "💻 Laptop", "is_unknown": False},
            {"device_class": "💻 Laptop", "is_unknown": False},
            {"device_class": "📱 Mobile", "is_unknown": False},
        ]
        result = self.fp.classify_environment(devices)
        assert result["type"] in ("home", "office", "mixed", "public", "unknown")
        assert 0 <= result["confidence"] <= 100


# ── PRIVACY UTILS TESTS ──────────────────────────────────────
class TestPrivacy:
    def test_hash_mac_is_deterministic(self):
        from utils.privacy import hash_mac
        assert hash_mac("aa:bb:cc:dd:ee:ff") == hash_mac("aa:bb:cc:dd:ee:ff")

    def test_hash_mac_not_reversible(self):
        from utils.privacy import hash_mac
        result = hash_mac("aa:bb:cc:dd:ee:ff")
        assert "aa:bb:cc:dd:ee:ff" not in result

    def test_hash_mac_has_ellipsis(self):
        from utils.privacy import hash_mac
        result = hash_mac("aa:bb:cc:dd:ee:ff")
        assert "..." in result

    def test_signal_to_bars(self):
        from utils.privacy import signal_to_bars
        assert signal_to_bars(-40) == 4
        assert signal_to_bars(-70) == 2
        assert signal_to_bars(-90) == 1
        assert signal_to_bars(-50) == 4
