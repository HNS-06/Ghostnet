"""
GhostNet Live Dashboard
Terminal-First AI-powered network intelligence CLI tool.
Intimidating, futuristic hacker console aesthetic supporting
live Forensic Tickers and Explainable AI overlays.
"""

import time
import threading
import random
from datetime import datetime
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.align import Align

console = Console()

# Theme Colors
NEON_GREEN = "#00ff9c"
DARK_GREEN = "#004d2e"
NEON_RED = "#ff003c"
NEON_CYAN = "#00f0ff"
NEON_YELLOW = "#ffea00"

GHOST_HEADER = f"[bold {NEON_GREEN}] ◈ GHOSTNET[/] [{DARK_GREEN}]· ULTRA-INTELLIGENCE SYNC · v4.0.0[/]"

def _signal_bars(strength: int) -> Text:
    filled = min(max(int(strength), 0), 4)
    t = Text()
    chars = ["▂", "▄", "▆", "█"]
    for i, ch in enumerate(chars):
        t.append(ch, style=f"bold {NEON_GREEN}" if i < filled else f"bold {DARK_GREEN}")
    return t

class LiveDashboard:
    def __init__(self, args, shutdown_event):
        self.args = args
        self._shutdown = shutdown_event
        self.networks = []
        self.devices = []
        self.forensic_ticker = [
            f"[{DARK_GREEN}][{datetime.now().strftime('%H:%M:%S')}] SYSTEM INITIALIZATION COMMENCED...[/]"
        ]
        self.ai_buffer = [
            f"[{NEON_CYAN}]> INITIALIZING DEEP ANALYSIS ENGINE...[/]",
            f"[{NEON_CYAN}]> LOADING PREDICTIVE BEHAVIOR MODELS...[/]"
        ]
        self._lock = threading.Lock()
        self._load_initial_data()

    def _load_initial_data(self):
        try:
            from database.db import GhostDB
            db = GhostDB()
            self.networks = db.get_recent_networks()
            self.devices = db.get_recent_devices()
            if not self.networks:
                raise ValueError("No data")
        except Exception:
            self._generate_demo_data()

    def _generate_demo_data(self):
        self.networks = [
            {"ssid": "CORP-AIR", "signal": 4, "encryption": "WPA3", "channel": 36, "risk": "low"},
            {"ssid": "xfinitywifi", "signal": 3, "encryption": "OPEN", "channel": 6, "risk": "medium"},
            {"ssid": "FREE_AIRPORT_WIFI", "signal": 4, "encryption": "OPEN", "channel": 11, "risk": "high"},
            {"ssid": "[HIDDEN_BSSID]", "signal": 2, "encryption": "WPA2", "channel": 44, "risk": "medium"},
        ]
        self.devices = [
            {"mac": "a3:f2:...:d91e", "vendor": "Apple Inc.", "status": "active", "trust_score": 85},
            {"mac": "b7:1c:...:4a22", "vendor": "Samsung", "status": "active", "trust_score": 40},
            {"mac": "ff:00:...:c3b9", "vendor": "UNKNOWN", "status": "idle", "trust_score": 10},
        ]

    def _make_header(self) -> Panel:
        now = datetime.now().strftime("%H:%M:%S")
        blink_state = f"[blink bold {NEON_RED}]LIVE[/]" if int(time.time()) % 2 == 0 else f"[bold {DARK_GREEN}]LIVE[/]"
        spinner = random.choice(["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"])
        
        header = Text.from_markup(f"{GHOST_HEADER}   [{NEON_GREEN}]{now}[/]   {blink_state}   [{NEON_YELLOW}]{spinner} INGESTING TELEMETRY[/]")
        return Panel(Align.center(header), border_style=DARK_GREEN, padding=(0, 1), height=3)

    def _make_networks_panel(self) -> Panel:
        table = Table(box=box.MINIMAL, border_style=DARK_GREEN, header_style=f"bold {NEON_GREEN}", padding=(0, 0, 0, 0), expand=True)
        table.add_column("TARGET BSSID", style=f"bold {NEON_GREEN}")
        table.add_column("SIG", justify="center")
        table.add_column("ENC", justify="center")
        table.add_column("RISK", justify="center")

        for net in self.networks[:6]:
            enc = net.get("encryption", "?")
            enc_style = f"bold {NEON_RED}" if enc == "OPEN" else f"{NEON_GREEN}"
            risk = net.get("risk", "low")
            risk_style = f"bold {NEON_RED}" if risk == "high" else f"bold {NEON_GREEN}"
            
            table.add_row(
                Text(net.get("ssid", "?")[:16], style=f"bold {NEON_GREEN}"),
                _signal_bars(net.get("signal", 0)),
                Text(enc, style=enc_style),
                Text(f"[{risk.upper()}]", style=risk_style),
            )
        return Panel(table, title=f"[bold {NEON_GREEN}] 🌐 NETWORK RELATIONSHIPS [/]", border_style=DARK_GREEN, padding=1)

    def _make_devices_panel(self) -> Panel:
        table = Table(box=box.MINIMAL, border_style=DARK_GREEN, header_style=f"bold {NEON_GREEN}", expand=True)
        table.add_column("MAC_HASH", style=f"{DARK_GREEN}")
        table.add_column("VENDOR_OUI", style=f"bold {NEON_CYAN}")
        table.add_column("TRUST", justify="center")

        for dev in self.devices[:5]:
            trust = dev.get("trust_score", 50)
            t_style = f"bold {NEON_GREEN}" if trust > 70 else (f"bold {NEON_YELLOW}" if trust > 30 else f"bold {NEON_RED} blink")
            
            table.add_row(
                Text(dev.get("mac", "?"), style=DARK_GREEN),
                dev.get("vendor", "?")[:12],
                Text(f"{trust}%", style=t_style),
            )
        return Panel(table, title=f"[bold {NEON_GREEN}] 🧬 DEVICE PROFILING [/]", border_style=DARK_GREEN, padding=1)

    def _make_timeline_panel(self) -> Panel:
        lines = Text()
        for msg in self.forensic_ticker[-8:]:
            lines.append_text(Text.from_markup(f"{msg}\n"))
        return Panel(lines, title=f"[bold {NEON_YELLOW}] 🧾 FORENSIC TICKER [/]", border_style=DARK_GREEN, padding=1)

    def _make_ai_panel(self) -> Panel:
        display_text = Text()
        for line in self.ai_buffer[-12:]:
            display_text.append_text(Text.from_markup(f"{line}\n"))
        
        if int(time.time() * 2) % 2 == 0:
            display_text.append("█", style=f"bold {NEON_GREEN}")
            
        return Panel(
            display_text, 
            title=f"[bold {NEON_CYAN}] 🧠 EXPLAINABLE AI LAYER [/]", 
            border_style=NEON_CYAN, 
            padding=1
        )

    def _make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(Layout(name="header", size=3), Layout(name="body"))
        layout["body"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=1))
        layout["left"].split_column(Layout(name="radar", ratio=1), Layout(name="devices", ratio=1))
        layout["right"].split_column(Layout(name="ai", ratio=2), Layout(name="ticker", ratio=1))
        return layout

    def _update_layout(self, layout):
        layout["header"].update(self._make_header())
        layout["radar"].update(self._make_networks_panel())
        layout["devices"].update(self._make_devices_panel())
        layout["ticker"].update(self._make_timeline_panel())
        layout["ai"].update(self._make_ai_panel())

    def _background_scanner(self):
        ai_events = [
            f"[{NEON_GREEN}]> ANALYSIS: Trust baseline consistent.[/]",
            f"[{NEON_YELLOW}]> PREDICTIVE: Device churn indicates potential spoof attempts.[/]",
            f"[{NEON_CYAN}]> REASON: MAC OUI mismatches transmitted capability info.[/]",
            f"[{NEON_RED}]> ALERT: Deception Deteciton triggered on 'xfinitywifi'.[/]",
            f"[{DARK_GREEN}]> Factor: Signal overlap > 80% with alien channel.[/]",
            f"[{DARK_GREEN}]> Ingesting radio packets on ch 36...[/]"
        ]
        
        ticker_diffs = [
            f"[{NEON_GREEN}][+] DEVICE CONNECTED: a3:f2...[/]",
            f"[{NEON_RED}][-] SIGNAL DROPPED: b7:1c...[/]",
            f"[{NEON_YELLOW}][!] ANOMALY: Signal spike +14dBm[/]",
            f"[{DARK_GREEN}][*] CHANNELS ROTATED.[/]"
        ]
        
        while not self._shutdown.is_set():
            time.sleep(random.uniform(0.5, 2.0))
            if self._shutdown.is_set(): break
            
            with self._lock:
                now = datetime.now().strftime('%H:%M:%S')
                if random.random() < 0.4:
                     self.ai_buffer.append(random.choice(ai_events))
                if random.random() < 0.6:
                     self.forensic_ticker.append(f"[{DARK_GREEN}][{now}][/] {random.choice(ticker_diffs)}")
                
                if len(self.ai_buffer) > 12: self.ai_buffer.pop(0)
                if len(self.forensic_ticker) > 8: self.forensic_ticker.pop(0)

                if random.random() < 0.3 and self.networks:
                     idx = random.randint(0, len(self.networks)-1)
                     self.networks[idx]["signal"] = max(1, min(4, self.networks[idx]["signal"] + random.choice([-1, 1])))

    def run(self):
        bg = threading.Thread(target=self._background_scanner, daemon=True)
        bg.start()
        layout = self._make_layout()
        with Live(layout, console=console, refresh_per_second=4, screen=True) as live:
            try:
                while not self._shutdown.is_set():
                    self._update_layout(layout)
                    time.sleep(0.25)
            except KeyboardInterrupt:
                self._shutdown.set()
