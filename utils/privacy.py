# GhostNet Utilities
import hashlib


def hash_mac(mac: str) -> str:
    """SHA-256 hash of MAC address for privacy-preserving storage."""
    return hashlib.sha256(mac.strip().lower().encode()).hexdigest()[:20] + "..."


def signal_to_bars(rssi: int) -> int:
    """Convert RSSI dBm to 1-4 signal bars."""
    if rssi >= -50:
        return 4
    elif rssi >= -65:
        return 3
    elif rssi >= -75:
        return 2
    else:
        return 1
