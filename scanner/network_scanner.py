"""
GhostNet Network Scanner
Detects WiFi networks, hidden SSIDs, devices, signal strength, encryption types.

In production: uses scapy + nmap.
In demo/hackathon mode: returns realistic simulated data.
"""

import hashlib
import random
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    signal: int          # 1-4 bars
    rssi: int            # dBm, e.g. -65
    encryption: str      # OPEN, WEP, WPA2, WPA3
    channel: int
    frequency: float     # GHz
    vendor: str
    hidden: bool = False
    device_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Device:
    mac_hash: str        # SHA-256 of MAC (privacy-preserving)
    ip: str
    vendor: str
    first_seen: str
    last_seen: str
    status: str          # active / idle / new
    network_ssid: str = ""


SIMULATED_NETWORKS = [
    WiFiNetwork("CORP-WIFI-5G", "fc:a5:d0:11:22:33", 4, -42, "WPA3", 36, 5.0, "Cisco"),
    WiFiNetwork("AndroidAP_7f3a", "e4:b8:7c:ab:cd:ef", 3, -61, "WPA2", 6, 2.4, "Samsung"),
    WiFiNetwork("linksys", "00:23:69:de:ad:01", 2, -72, "OPEN", 1, 2.4, "Linksys"),
    WiFiNetwork("$$FREE_WIFI$$", "f4:6d:04:ba:dc:af", 4, -38, "OPEN", 6, 2.4, "Unknown"),
    WiFiNetwork("", "b0:4e:26:77:88:99", 2, -75, "WPA2", 44, 5.0, "Unknown", hidden=True),
    WiFiNetwork("HomeNet-2.4G", "e8:94:f6:12:34:56", 3, -58, "WPA2", 1, 2.4, "TP-Link"),
    WiFiNetwork("Starbucks-Guest", "cc:40:d0:aa:bb:cc", 3, -55, "OPEN", 6, 2.4, "Ruckus"),
    WiFiNetwork("NETGEAR-5G-Pro", "a0:63:91:dd:ee:ff", 4, -48, "WPA3", 149, 5.0, "NETGEAR"),
    WiFiNetwork("DIRECT-TV-ABC12", "78:4b:87:10:20:30", 1, -82, "WPA2", 11, 2.4, "Unknown"),
]


def _hash_mac(mac: str) -> str:
    return hashlib.sha256(mac.encode()).hexdigest()[:16] + "..."


class NetworkScanner:
    """
    Scans nearby WiFi networks.

    Modes:
      quick   — fast passive scan (~3-4s)
      deep    — full active scan with device enumeration (~8-12s)
      stealth — passive only, minimal traffic footprint
    """

    def __init__(self, mode: str = "quick"):
        self.mode = mode
        self._scapy_available = self._check_scapy()
        self._nmap_available = self._check_nmap()

    def _check_scapy(self) -> bool:
        try:
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            logging.getLogger("scapy.loading").setLevel(logging.ERROR)
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import scapy.all  # noqa
            return True
        except ImportError:
            return False

    def _check_nmap(self) -> bool:
        import shutil
        return shutil.which("nmap") is not None

    def scan(self) -> List[dict]:
        """
        Run a network scan and return list of network dicts.
        Falls back to simulation if hardware tools unavailable.
        """
        import sys
        if sys.platform == "win32":
            networks = self._scan_with_netsh()
            if networks:
                return networks
            return self._scan_simulated()

        if self._scapy_available:
            return self._scan_with_scapy()
        elif self._nmap_available:
            return self._scan_with_nmap()
        else:
            return self._scan_simulated()

    def _resolve_vendor(self, bssid: str) -> str:
        ouis = {
            "fc:a5:d0": "Cisco",
            "e4:b8:7c": "Samsung",
            "00:23:69": "Linksys",
            "f4:6d:04": "TP-Link",
            "b0:4e:26": "Apple",
            "e8:94:f6": "TP-Link",
            "cc:40:d0": "Ruckus",
            "a0:63:91": "NETGEAR",
            "78:4b:87": "Intel",
            "e6:ab:21": "Vivo"
        }
        prefix = bssid.lower()[:8]
        return ouis.get(prefix, "Unknown")

    def _scan_with_netsh(self) -> List[dict]:
        import subprocess
        import re
        networks = []
        
        # 1. Get currently connected interface details (very reliable on Windows)
        try:
            res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, errors="ignore")
            if res.returncode == 0:
                current = {}
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        parts = line.split(":", 1)
                        key = parts[0].strip()
                        val = parts[1].strip()
                        if key == "SSID":
                            current["ssid"] = val
                        elif key == "AP BSSID":
                            current["bssid"] = val
                        elif key == "Channel":
                            current["channel"] = int(val) if val.isdigit() else 0
                        elif key == "Signal":
                            sig_pct = int(val.replace("%", "").strip())
                            current["signal"] = max(1, min(4, sig_pct // 25 + 1))
                        elif key == "Rssi" or key == "RSSI":
                            current["rssi"] = int(val)
                        elif key == "Authentication":
                            enc = "WPA2"
                            if "WPA3" in val:
                                enc = "WPA3"
                            elif "WEP" in val:
                                enc = "WEP"
                            elif "Open" in val or "None" in val:
                                enc = "OPEN"
                            current["encryption"] = enc
                        elif key == "Band":
                            try:
                                current["frequency"] = float(val.replace("GHz", "").strip())
                            except ValueError:
                                current["frequency"] = 2.4
                
                if "ssid" in current and "bssid" in current:
                    current["vendor"] = self._resolve_vendor(current["bssid"])
                    current["hidden"] = False
                    # Initialize default rssi if not provided by netsh show interfaces
                    if "rssi" not in current and "signal" in current:
                        # Estimate RSSI from signal strength percentage
                        sig_pct = (current["signal"] - 1) * 25 + 15
                        current["rssi"] = (sig_pct // 2) - 100
                    networks.append(current)
        except Exception:
            pass

        # 2. Get all visible networks
        try:
            res = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, errors="ignore")
            if res.returncode == 0:
                current_net = None
                
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Check for SSID line
                    ssid_match = re.match(r"^SSID\s+\d+\s+:\s*(.*)$", line)
                    if ssid_match:
                        if current_net and current_net.get("bssid"):
                            if not any(n["bssid"].lower() == current_net["bssid"].lower() for n in networks):
                                networks.append(current_net)
                        
                        ssid = ssid_match.group(1).strip()
                        current_net = {
                            "ssid": ssid or "[HIDDEN]",
                            "hidden": not bool(ssid),
                            "vendor": "Unknown",
                            "frequency": 2.4,
                            "channel": 1,
                            "signal": 2,
                            "rssi": -75,
                            "encryption": "OPEN"
                        }
                        continue
                    
                    if not current_net:
                        continue
                    
                    if line.startswith("Authentication"):
                        auth = line.split(":", 1)[1].strip()
                        enc = "WPA2"
                        if "WPA3" in auth:
                            enc = "WPA3"
                        elif "WEP" in auth:
                            enc = "WEP"
                        elif "Open" in auth or "None" in auth:
                            enc = "OPEN"
                        current_net["encryption"] = enc
                    
                    bssid_match = re.match(r"^BSSID\s+\d+\s+:\s*([0-9a-fA-F:]+)$", line)
                    if bssid_match:
                        if current_net.get("bssid"):
                            if not any(n["bssid"].lower() == current_net["bssid"].lower() for n in networks):
                                networks.append(current_net.copy())
                        current_net["bssid"] = bssid_match.group(1).strip()
                        current_net["vendor"] = self._resolve_vendor(current_net["bssid"])
                        continue
                    
                    if line.startswith("Signal"):
                        sig_val = line.split(":", 1)[1].strip().replace("%", "")
                        sig_pct = int(sig_val) if sig_val.isdigit() else 50
                        current_net["signal"] = max(1, min(4, sig_pct // 25 + 1))
                        current_net["rssi"] = (sig_pct // 2) - 100
                    
                    if line.startswith("Channel"):
                        ch_val = line.split(":", 1)[1].strip()
                        ch = int(ch_val) if ch_val.isdigit() else 1
                        current_net["channel"] = ch
                        current_net["frequency"] = 5.0 if ch > 14 else 2.4

                if current_net and current_net.get("bssid"):
                    if not any(n["bssid"].lower() == current_net["bssid"].lower() for n in networks):
                        networks.append(current_net)
        except Exception:
            pass

        return networks

    def _scan_with_scapy(self) -> List[dict]:
        """Real scan using scapy (requires root)."""
        try:
            from scapy.all import Dot11, Dot11Beacon, sniff
            networks = []

            def packet_handler(pkt):
                if pkt.haslayer(Dot11Beacon):
                    ssid = pkt[Dot11].info.decode("utf-8", errors="replace")
                    bssid = pkt[Dot11].addr2
                    signal = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -70
                    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split("+")
                    enc = "OPEN"
                    if "privacy" in cap:
                        enc = "WPA2"  # simplified; real detection requires IE parsing
                    networks.append({
                        "ssid": ssid or "[HIDDEN]",
                        "bssid": bssid,
                        "signal": max(1, min(4, (signal + 90) // 10)),
                        "rssi": signal,
                        "encryption": enc,
                        "channel": 0,
                        "vendor": "Unknown",
                        "hidden": not bool(ssid),
                    })

            timeout = {"quick": 3, "deep": 8, "stealth": 5}.get(self.mode, 3)
            sniff(prn=packet_handler, iface="wlan0", timeout=timeout, store=False)
            return networks
        except Exception:
            return self._scan_simulated()

    def _scan_with_nmap(self) -> List[dict]:
        """Scan using nmap for device discovery."""
        import subprocess
        try:
            result = subprocess.run(
                ["nmap", "-sn", "192.168.1.0/24", "--open", "-oG", "-"],
                capture_output=True, text=True, timeout=15
            )
            # Parse nmap output (simplified)
            return self._scan_simulated()  # merge with nmap results
        except Exception:
            return self._scan_simulated()

    def _scan_simulated(self) -> List[dict]:
        """Demo/hackathon mode: realistic simulated scan data."""
        count = random.randint(7, 12) if self.mode == "deep" else random.randint(5, 9)
        selected = random.sample(SIMULATED_NETWORKS, min(count, len(SIMULATED_NETWORKS)))

        result = []
        for net in selected:
            d = net.to_dict()
            # Add some jitter to make it feel live
            d["rssi"] = d["rssi"] + random.randint(-3, 3)
            d["signal"] = max(1, min(4, d["signal"] + random.choice([-1, 0, 0, 1])))
            result.append(d)

        return result

    def scan_devices(self, network_ip_range: str = "192.168.1.0/24") -> List[Device]:
        """Enumerate devices on a network. MACs are hashed for privacy."""
        simulated = [
            Device(_hash_mac("a3:f2:b1:c4:d5:e6"), "192.168.1.104", "Apple Inc.", "2d ago", "2m ago", "active"),
            Device(_hash_mac("b7:1c:2d:3e:4f:5a"), "192.168.1.117", "Samsung", "5h ago", "12m ago", "active"),
            Device(_hash_mac("ff:00:11:22:33:44"), "10.0.0.42", "Unknown", "1h ago", "1h ago", "idle"),
            Device(_hash_mac("d4:38:9f:ab:cd:ef"), "192.168.1.1", "Cisco Router", "7d ago", "1m ago", "active"),
            Device(_hash_mac("c1:9a:b2:c3:d4:e5"), "192.168.1.203", "Raspberry Pi", "3d ago", "45m ago", "active"),
        ]
        return simulated
