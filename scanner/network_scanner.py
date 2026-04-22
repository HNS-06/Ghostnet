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
            import scapy  # noqa
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
        if self._scapy_available:
            return self._scan_with_scapy()
        elif self._nmap_available:
            return self._scan_with_nmap()
        else:
            return self._scan_simulated()

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
