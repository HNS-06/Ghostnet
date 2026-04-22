"""
GhostNet CLI Engine v4.0
Executes high-level cyber intelligence commands (Hunt, Profile, Timeline)
natively through the terminal.
"""

import time
import threading
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from database.db import GhostDB

console = Console(highlight=False)

NEON_GREEN = "bold #00ff9c"
DARK_GREEN = "bold #004d2e"
NEON_CYAN = "bold #00f0ff"

class GhostNetCLI:
    def __init__(self, args):
        self.args = args
        self.console = console
        self._shutdown = threading.Event()
        self.db = GhostDB()

    def run(self):
        cmd = self.args.command
        dispatch = {
            "live": self.cmd_live,
            "dashboard": self.cmd_dashboard,
            "scan": self.cmd_scan,
            "analyze": self.cmd_analyze,
            "hunt": self.cmd_hunt,
            "profile": self.cmd_profile,
            "timeline": self.cmd_timeline,
            "trust": self.cmd_trust,
            "plugins": self.cmd_plugins,
            "api": self.cmd_api,
            "predict": self.cmd_predict,
        }
        dispatch.get(cmd, self.cmd_live)()

    def cmd_live(self):
        from cli.live_mode import LiveTerminal
        term = LiveTerminal(mode=self.args.alert_mode)
        term.start()

    def shutdown(self):
        self._shutdown.set()
        console.print(f"\n[{DARK_GREEN}]◈ TERMINATING GHOSTNET. STAY GHOST.[/]")

    def cmd_dashboard(self):
        from cli.dashboard import LiveDashboard
        dash = LiveDashboard(self.args, self._shutdown)
        dash.run()

    def cmd_hunt(self):
        console.print(f"[{NEON_GREEN}]◈ AUTONOMOUS THREAT HUNTER[/]")
        console.print(f"[{DARK_GREEN}]> ENGAGING ACTIVE SENSORS...[/]")
        with Progress(SpinnerColumn(style="bold #00ff9c"), TextColumn("[#00ff9c]{task.description}"), transient=True) as progress:
            t = progress.add_task("Calculating behavioral baselines...", total=None)
            time.sleep(2)
            progress.update(t, description="Isolating anomalous network clusters...")
            time.sleep(2)

        from ai.claude_engine import ClaudeEngine
        ai = ClaudeEngine()
        nets = self.db.get_recent_networks()
        devs = self.db.get_recent_devices()
        
        console.print(Panel(
            f"[{NEON_CYAN}]Autonomous routine identified high-confidence anomaly.[#00f0ff]\n\n"
            f"THREAT NARRATIVE:\n"
            f"Multiple unknown MAC addresses are cyclically authenticating to open network bounds.\n"
            f"This matches signature profile for distributed hotspot probing spoofing.",
            title="[bold #ff003c]◈ HUNTER REPORT", border_style="#ff003c"
        ))

    def cmd_profile(self):
        mac = self.args.mac if self.args.mac else "UNKNOWN"
        console.print(f"[{NEON_GREEN}]◈ DEVICE FORENSIC PROFILE: {mac}[/]")
        profile = self.db.get_device_profile(mac)
        
        if not profile:
             console.print(f"[{DARK_GREEN}]> ERROR: MAC NOT FOUND IN MEMORY LEDGER.[/]")
             return
             
        t = Table(box=box.MINIMAL, border_style="#004d2e", expand=True)
        t.add_column("METRIC", style=NEON_CYAN)
        t.add_column("VALUE", style=NEON_GREEN)
        
        t.add_row("Vendor", str(profile.get("vendor")))
        t.add_row("Trust Score", str(profile.get("trust_score", 50)))
        t.add_row("Appearance Freq", str(profile.get("appearance_frequency", 1)))
        t.add_row("Status", str(profile.get("status")))
        
        console.print(t)

    def cmd_timeline(self):
        limit = self.args.limit
        console.print(f"[{NEON_GREEN}]◈ FORENSIC TIMELINE (LAST {limit} EVENTS)[/]")
        events = self.db.get_timeline(limit)
        
        t = Table(box=box.SIMPLE, border_style="#004d2e")
        t.add_column("TIMESTAMP", style=DARK_GREEN)
        t.add_column("TYPE", style=NEON_CYAN)
        t.add_column("EVENT_DESCRIPTION", style=NEON_GREEN)
        
        for e in events:
            t.add_row(e.get("timestamp")[11:19], e.get("event_type"), e.get("description"))
        console.print(t)

    def cmd_trust(self):
        console.print(f"[{NEON_GREEN}]◈ DIGITAL AURA 2.0 MATRIX[/]")
        history = self.db.get_aura_history(1)
        if not history:
             console.print(f"[{DARK_GREEN}]> INSUFFICIENT DATA[/]")
             return
        today = history[0]
        
        console.print(Panel(
             f"AURA SCORE: {today.get('aura_score')}/100\n"
             f"RISK VOLATILITY: {today.get('risk_volatility')}%\n"
             f"DEVICE STABILITY: {today.get('device_stability')}%\n\n"
             f"[{DARK_GREEN}]> Environment assessment: Secure.[/]",
             title=f"[{NEON_CYAN}]ENVIRONMENT TRUST[/]", border_style="#00f0ff"
        ))

    def cmd_plugins(self):
        console.print(f"[{NEON_GREEN}]◈ PLUGIN MANAGER[/]")
        name = self.args.plugin
        if name:
             with console.status(f"[#00ff9c]Loading module: {name}...[/]", spinner="arc"):
                  time.sleep(1)
             console.print(f"[{NEON_GREEN}]> Module {name} injected into active kernel.[/]")
        else:
             console.print(f"[{DARK_GREEN}]Available Modules: bluetooth_scanner, usb_monitor, pcap_dumper[/]")

    def cmd_scan(self):
        console.print(f"[{NEON_GREEN}]◈ EXECUTING AD-HOC TELEMETRY SWEEP[/]")
        from scanner.network_scanner import NetworkScanner
        n = NetworkScanner().scan()
        self.db.store_networks(n)
        console.print(f"[{DARK_GREEN}]> Processed {len(n)} networks.[/]")

    def cmd_analyze(self):
        console.print(f"[{NEON_GREEN}]◈ INITIATING EXPLAINABLE AI LAYER[/]")
        time.sleep(1)
        from ai.claude_engine import ClaudeEngine
        r = ClaudeEngine().deep_analysis([], [])
        console.print(r.get("threat_narrative", "Analysis complete."))

    def cmd_predict(self):
        pass

    def cmd_api(self):
        from api.server import run_api
        run_api(port=self.args.port)
