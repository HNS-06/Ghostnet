#!/usr/bin/env python3
"""
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ██╗███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔██╗ ██║█████╗     ██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚████║███████╗   ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝

  Ultra-Intelligent Cyber Intelligence System · v4.0.0
  "See what others can't. Stay ghost."
"""

import sys
import argparse
from cli.engine import GhostNetCLI

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(
        prog="ghostnet",
        description="GhostNet v4.0 — Ultra-Intelligent Cyber Intelligence System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Core Commands:
  live        Launch Live Intelligence Pipeline (Zero-noise, Event-Driven)
  dashboard   Legacy animated terminal dashboard
  scan        Perform ad-hoc telemetry collection
  analyze     Execute Explainable AI layer
  hunt        [NEW] Autonomous Threat Hunter mode
  profile     [NEW] Deep-dive behavioral analysis on MAC
  timeline    [NEW] Ledger of all environment micro-events
  trust       [NEW] Review Digital Aura parameters
  plugins     [NEW] Load expansion modules (e.g. bluetooth)
  api         Start REST API for external integrations

Examples:
  ghostnet live --alert-mode paranoid
  ghostnet hunt
  ghostnet profile --mac aa:bb:cc:dd
  ghostnet timeline --limit 100
        """
    )
    
    commands = ["scan", "analyze", "alert", "predict", "dashboard", "live", "api", "hunt", "profile", "timeline", "trust", "plugins"]
    parser.add_argument("command", nargs="?", default="live", choices=commands)
    
    parser.add_argument("--mode", choices=["quick", "deep", "stealth"], default="quick")
    parser.add_argument("--alert-mode", choices=["chill", "balanced", "paranoid"], default="balanced")
    parser.add_argument("--mac", type=str, help="Target MAC address for profiling")
    parser.add_argument("--limit", type=int, default=50, help="Output limit")
    parser.add_argument("--plugin", type=str, help="Plugin name to load")
    parser.add_argument("--network", type=str, help="Target network SSID for analysis")
    
    args = parser.parse_args()
    cli = GhostNetCLI(args)

    try:
        cli.run()
    except KeyboardInterrupt:
        cli.shutdown()
        sys.exit(0)

if __name__ == "__main__":
    main()
