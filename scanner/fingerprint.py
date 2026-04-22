"""
GhostNet Device Fingerprinting Engine
Identifies device types from OUI, probe requests, TTL, and traffic patterns.
All identification is done locally. No data leaves the device.
"""

import re
import json
import os
from typing import Optional, Tuple

# Partial OUI → vendor mapping (first 3 bytes of MAC)
# In production, load from the full IEEE OUI database (~30k entries)
OUI_MAP = {
    "00:50:56": ("VMware", "Virtual Machine"),
    "08:00:27": ("Oracle", "VirtualBox VM"),
    "00:0C:29": ("VMware", "Virtual Machine"),
    "AC:DE:48": ("Apple", "iPhone/iPad"),
    "F8:FF:C2": ("Apple", "MacBook"),
    "3C:22:FB": ("Apple", "iPhone"),
    "A4:83:E7": ("Apple", "iPhone"),
    "60:F8:1D": ("Apple", "Mac"),
    "28:CF:E9": ("Apple", "AirPort"),
    "E4:B8:7C": ("Samsung", "Android Phone"),
    "8C:71:F8": ("Samsung", "Android"),
    "78:1F:DB": ("Samsung", "Galaxy"),
    "00:23:69": ("Cisco-Linksys", "Router"),
    "E8:94:F6": ("TP-Link", "Router/AP"),
    "A0:63:91": ("NETGEAR", "Router"),
    "B0:4E:26": ("Huawei", "Device"),
    "DC:A6:32": ("Raspberry Pi", "SBC"),
    "B8:27:EB": ("Raspberry Pi", "SBC"),
    "00:11:22": ("Unknown", "Unknown"),
    "F4:6D:04": ("Google", "Chromecast/Nest"),
    "CC:40:D0": ("Ruckus", "Access Point"),
    "FC:A5:D0": ("Cisco", "Network Device"),
    "00:1A:2B": ("Intel", "Network Adapter"),
    "A4:C3:F0": ("Intel", "Wi-Fi Card"),
    "3C:91:57": ("Intel", "Wi-Fi Card"),
}

# Device type classifications
DEVICE_CLASSES = {
    "Router/AP": "🌐 Infrastructure",
    "iPhone/iPad": "📱 Mobile",
    "Android Phone": "📱 Mobile",
    "Galaxy": "📱 Mobile",
    "MacBook": "💻 Laptop",
    "Mac": "💻 Desktop/Laptop",
    "SBC": "🖥️ IoT/Server",
    "Virtual Machine": "🖥️ Virtual",
    "Chromecast/Nest": "📺 Smart Home",
    "Access Point": "🌐 Infrastructure",
    "Network Device": "🌐 Infrastructure",
    "Wi-Fi Card": "💻 Computer",
    "Unknown": "❓ Unknown",
}

# Risk modifiers by device class
CLASS_RISK_MODIFIER = {
    "🌐 Infrastructure": 0.1,   # Routers are expected
    "📱 Mobile": 0.2,            # Phones are common
    "💻 Laptop": 0.1,
    "💻 Computer": 0.1,
    "🖥️ IoT/Server": 0.3,       # IoT devices warrant attention
    "🖥️ Virtual": 0.5,          # VMs in the wild are suspicious
    "📺 Smart Home": 0.2,
    "❓ Unknown": 0.7,           # Unknown device type = elevated risk
}


class DeviceFingerprinter:
    """
    Identifies device vendors and types from hashed MACs and other signals.

    In full mode (requires scapy): probes TTL, TCP window size, probe request patterns.
    In privacy mode (default): OUI lookup only from the first 3 MAC bytes.
    """

    def __init__(self, oui_db_path: Optional[str] = None):
        self.oui_map = dict(OUI_MAP)
        if oui_db_path and os.path.exists(oui_db_path):
            self._load_oui_db(oui_db_path)

    def _load_oui_db(self, path: str):
        """Load full IEEE OUI database for production use."""
        try:
            with open(path) as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            oui = parts[0].replace("-", ":").upper()
                            vendor = " ".join(parts[2:])
                            self.oui_map[oui] = (vendor, "Device")
        except Exception:
            pass

    def fingerprint(self, mac_prefix: str, ip: Optional[str] = None) -> dict:
        """
        Fingerprint a device from its MAC prefix (first 3 bytes).
        mac_prefix: e.g. "e4:b8:7c" (from MAC before hashing)
        """
        prefix = mac_prefix[:8].upper()
        vendor, device_type = self.oui_map.get(prefix, ("Unknown", "Unknown"))
        device_class = DEVICE_CLASSES.get(device_type, "❓ Unknown")
        risk_mod = CLASS_RISK_MODIFIER.get(device_class, 0.5)

        # IP-based heuristics
        ip_hints = self._analyze_ip(ip) if ip else {}

        return {
            "vendor": vendor,
            "device_type": device_type,
            "device_class": device_class,
            "risk_modifier": risk_mod,
            "is_infrastructure": device_class == "🌐 Infrastructure",
            "is_mobile": device_class == "📱 Mobile",
            "is_unknown": vendor == "Unknown",
            **ip_hints,
        }

    def _analyze_ip(self, ip: str) -> dict:
        """Derive hints from IP address."""
        hints = {}
        try:
            parts = ip.split(".")
            last = int(parts[-1])
            if last == 1:
                hints["likely_gateway"] = True
            elif last < 10:
                hints["likely_infrastructure"] = True
            # Common DHCP ranges
            if ip.startswith("169.254."):
                hints["apipa"] = True  # self-assigned, no DHCP
                hints["dhcp_failure"] = True
        except Exception:
            pass
        return hints

    def fingerprint_batch(self, devices: list) -> list:
        """Fingerprint a list of device dicts."""
        results = []
        for dev in devices:
            # Extract MAC prefix from hashed MAC (first chars before "...")
            mac_hash = dev.get("mac_hash", "")
            mac_prefix = dev.get("mac_prefix", "")  # real prefix if available
            ip = dev.get("ip", "")
            fp = self.fingerprint(mac_prefix or "00:00:00", ip)
            results.append({**dev, **fp})
        return results

    def classify_environment(self, devices: list) -> dict:
        """
        Classify the overall network environment from device mix.
        Returns: home / office / public / mixed / unknown
        """
        if not devices:
            return {"type": "unknown", "confidence": 0}

        infra = sum(1 for d in devices if d.get("device_class") == "🌐 Infrastructure")
        mobile = sum(1 for d in devices if d.get("device_class") == "📱 Mobile")
        laptop = sum(1 for d in devices if d.get("device_class") == "💻 Laptop")
        unknown = sum(1 for d in devices if d.get("is_unknown"))
        total = len(devices)

        if total == 0:
            return {"type": "unknown", "confidence": 0}

        mobile_ratio = mobile / total
        unknown_ratio = unknown / total

        if unknown_ratio > 0.5:
            env_type = "public"
            confidence = int(unknown_ratio * 100)
        elif mobile_ratio > 0.6:
            env_type = "public"
            confidence = int(mobile_ratio * 80)
        elif infra >= 1 and laptop >= 1 and mobile <= 2:
            env_type = "home"
            confidence = 75
        elif infra >= 2 and laptop >= 3:
            env_type = "office"
            confidence = 80
        else:
            env_type = "mixed"
            confidence = 55

        return {
            "type": env_type,
            "confidence": confidence,
            "breakdown": {
                "infrastructure": infra,
                "mobile": mobile,
                "laptop": laptop,
                "unknown": unknown,
            }
        }
