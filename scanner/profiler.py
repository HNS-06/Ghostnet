"""
GhostNet Profiler & Stream Processor
Handles device behavior profiling, long-term memory pattern tracking, 
and computing real-time diff streams for the terminal UI.
"""

from datetime import datetime
from database.db import GhostDB

class ProfilerEngine:
    def __init__(self, db: GhostDB):
        self.db = db
        self.last_seen_macs = set()
        self.last_seen_ssids = set()

    def process_scan_stream(self, networks: list, devices: list) -> list:
        """
        Calculates diffs (+ New Device, - Lost Signal) and flags anomalies.
        Returns a list of forensic ticker messages.
        """
        current_macs = {d.mac_hash for d in devices}
        current_ssids = {n.get("ssid", "[HIDDEN]") for n in networks}

        stream_events = []

        # Analyze MAC diffs
        new_macs = current_macs - self.last_seen_macs
        dropped_macs = self.last_seen_macs - current_macs

        for mac in new_macs:
            dev = next((d for d in devices if d.mac_hash == mac), None)
            vendor = dev.vendor if dev else "Unknown"
            msg = f"[+] NEW DEVICE DETECTED: {mac[:8]}... ({vendor})"
            stream_events.append(msg)
            self.db.log_event("DEVICE_APPEARED", msg, related_mac=mac)

        for mac in dropped_macs:
            msg = f"[-] DEVICE LOST SIGNAL: {mac[:8]}..."
            stream_events.append(msg)
            self.db.log_event("DEVICE_DROPPED", msg, related_mac=mac)

        # Analyze Network diffs
        new_ssids = current_ssids - self.last_seen_ssids
        dropped_ssids = self.last_seen_ssids - current_ssids

        for ssid in new_ssids:
            msg = f"[!] NEW NETWORK DETECTED: {ssid}"
            stream_events.append(msg)
            self.db.log_event("NETWORK_APPEARED", msg, related_ssid=ssid)

        for ssid in dropped_ssids:
            msg = f"[-] NETWORK LOST: {ssid}"
            stream_events.append(msg)
            self.db.log_event("NETWORK_DROPPED", msg, related_ssid=ssid)

        self.last_seen_macs = current_macs
        self.last_seen_ssids = current_ssids

        return stream_events

    def profile_device(self, mac_hash: str) -> dict:
        """
        Retrieves long-term behavior patterns for a MAC.
        """
        profile = self.db.get_device_profile(mac_hash)
        if not profile:
            return {"status": "unknown", "trust_score": 0, "summary": "No historical behavior logged."}
        
        freq = profile.get("appearance_frequency", 1)
        trust = profile.get("trust_score", 50)
        
        # Simple profiling heuristics
        if freq > 50 and trust > 70:
            classification = "Likely Employee / Infrastructure"
        elif freq < 3:
            classification = "Transient / Unknown"
            trust = max(0, trust - 10)
        else:
            classification = "Repeated Visitor"
            
        return {
            "mac_hash": mac_hash,
            "classification": classification,
            "trust_score": trust,
            "frequency": freq,
            "summary": f"Device seen {freq} times. {classification}."
        }

    def correlate_clusters(self, networks: list, devices: list) -> list:
        """
        Identifies relationships between devices and networks based on signal timings.
        """
        clusters = []
        for n in networks:
            ssid = n.get("ssid", "[HIDDEN]")
            # Dummy logic: correlate based on matching bssids or signal strengths
            # In a real tool this uses packet capture of probes
            associated = [d.mac_hash for d in devices if d.network_ssid == ssid]
            if associated:
                clusters.append({
                    "ssid": ssid,
                    "connected_macs": associated,
                    "count": len(associated)
                })
        return clusters
