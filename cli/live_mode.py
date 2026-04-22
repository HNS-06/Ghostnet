"""
GhostNet Live Mode
The strict, zero-noise, split-layout intelligence terminal.
Connects strictly to the Central Event Pipeline queue.
"""

import queue
import time
import threading
from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text

from core.event_pipeline import CentralPipeline

console = Console(highlight=False)

DARK_GREEN = "#004d2e"
NEON_GREEN = "#00ff9c"
ALERT_RED = "#ff003c"
CYAN = "#00f0ff"
DIM_TXT = "dim white"


def split_layout() -> Layout:
    l = Layout()
    l.split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )
    l["left"].split_column(
        Layout(name="radar", size=15),
        Layout(name="scan_log")
    )
    l["right"].split_column(
        Layout(name="alerts", ratio=1),
        Layout(name="ai", ratio=1)
    )
    return l


class LiveTerminal:
    def __init__(self, mode="balanced"):
        self.mode = mode
        self.ui_queue = queue.Queue()
        self.pipeline = CentralPipeline(mode, self.ui_queue)
        
        self.scan_logs = []
        self.alerts = []
        self.ai_insights = []
        self.state_cache = None

    def _render_radar(self) -> Panel:
        t = Text()
        if not self.state_cache:
            t.append("AWAITING INITIAL STATE...", style=DARK_GREEN)
        else:
            t.append(f"TOTAL NETWORKS: {len(self.state_cache.networks)}\n", style=NEON_GREEN)
            t.append(f"TOTAL DEVICES: {len(self.state_cache.devices)}\n\n", style=CYAN)
            for ssid, net in list(self.state_cache.networks.items())[:5]:
                t.append(f"◈ {ssid[:14]:<15} ", style=DARK_GREEN)
                t.append(f"[{net.get('encryption')}]", style=ALERT_RED if net.get("encryption") == "OPEN" else NEON_GREEN)
                t.append("\n")
        return Panel(t, title="[bold #00ff9c] OBSERVER STATE [/]", border_style=DARK_GREEN)

    def _render_scan_logs(self) -> Panel:
        t = Text()
        for log in self.scan_logs:
            t.append(log + "\n")
        return Panel(t, title=f"[{DIM_TXT}] [SCAN UPDATE] [/]", border_style=DARK_GREEN)

    def _render_alerts(self) -> Panel:
        t = Text()
        for a in self.alerts:
            t.append("[ALERT]\n", style=DARK_GREEN)
            t.append(f"⚠ {a['severity']}\n", style=f"blink bold {ALERT_RED}")
            t.append(f"{a['body']}\n\n", style="white")
        if not self.alerts:
            t.append("NO ESCALATIONS IN QUEUE.", style=DARK_GREEN)
        return Panel(t, title=f"[bold {ALERT_RED}] ESCALATIONS [/]", border_style=ALERT_RED)

    def _render_ai(self) -> Panel:
        t = Text()
        for i in self.ai_insights:
            t.append("[AI INSIGHT]\n", style=DARK_GREEN)
            t.append(f"{i['body']}\n\n", style=CYAN)
        if not self.ai_insights:
            t.append("WAITING FOR ESCALATION TRIGGER...", style=DARK_GREEN)
        return Panel(t, title=f"[bold {CYAN}] COGNITIVE LAYER [/]", border_style=DARK_GREEN)

    def start(self):
        console.clear()
        console.print(f"[{NEON_GREEN}]> INITIATING CONTINUOUS INTELLIGENCE PIPELINE (MODE: {self.mode.upper()})[/]")
        time.sleep(1)
        
        # Start the background pipeline thread
        pipeline_thread = threading.Thread(target=self.pipeline.run, daemon=True)
        pipeline_thread.start()

        layout = split_layout()

        try:
            with Live(layout, console=console, refresh_per_second=5, screen=True):
                while True:
                    # Process UI Queue without blocking indefinitely
                    while not self.ui_queue.empty():
                        msg = self.ui_queue.get()
                        t = msg["type"]
                        
                        if t == "STATE_UPDATE":
                            self.state_cache = msg["data"]
                        elif t == "SCAN_UPDATE":
                            self.scan_logs.insert(0, f"[{time.strftime('%H:%M:%S')}] {msg['msg']}")
                            if len(self.scan_logs) > 12: self.scan_logs.pop()
                        elif t == "ALERT":
                            self.alerts.insert(0, msg)
                            if len(self.alerts) > 3: self.alerts.pop()
                        elif t == "AI_INSIGHT":
                            self.ai_insights.insert(0, msg)
                            if len(self.ai_insights) > 3: self.ai_insights.pop()
                    
                    # Re-render panels
                    layout["radar"].update(self._render_radar())
                    layout["scan_log"].update(self._render_scan_logs())
                    layout["alerts"].update(self._render_alerts())
                    layout["ai"].update(self._render_ai())
                    
                    time.sleep(0.2)
        except KeyboardInterrupt:
            self.pipeline.stop()
            console.print(f"\n[{DARK_GREEN}]> CENTRAL LOOP TERMINATED.[/]")
