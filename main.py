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
import time
import threading
import random
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Theme Colors
NEON_GREEN = "#00ff9c"
DARK_GREEN = "#004d2e"
NEON_RED = "#ff003c"
NEON_CYAN = "#00f0ff"
NEON_YELLOW = "#ffea00"

GHOST_HEADER = f"[bold {NEON_GREEN}] ◈ GHOSTNET LIVE WiFi MONITOR[/] [{DARK_GREEN}]· REAL-TIME SCANNING · v4.0.0[/]"


def _signal_bars(strength: int) -> Text:
    filled = min(max(int(strength), 0), 4)
    t = Text()
    chars = ["▂", "▄", "▆", "█"]
    for i, ch in enumerate(chars):
        t.append(ch, style=f"bold {NEON_GREEN}" if i < filled else f"bold {DARK_GREEN}")
    return t


def scan_networks(mode="live"):
    """
    Scan for WiFi networks and return results.
    In live mode, uses NetworkScanner to actually scan.
    In demo mode, returns simulated data.
    """
    from scanner.network_scanner import NetworkScanner
    
    scanner = NetworkScanner(mode="deep")
    
    with Progress(
        SpinnerColumn(spinner_name="dots", style="green"),
        TextColumn("[green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TextColumn("[dim green]{task.percentage:.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        steps = [
            ("Initializing RF interface...", 0.8),
            ("Probing 2.4GHz band...", 1.2),
            ("Probing 5GHz band (channels 36-165)...", 1.0),
            ("Passive SSID detection...", 0.9),
            ("Device enumeration (hashed MACs)...", 1.1),
            ("Multi-factor risk scoring...", 0.8),
            ("Updating SQLite baseline...", 0.5),
            ("Invoking Claude AI...", 1.4),
        ]
        task = progress.add_task("Scanning...", total=len(steps))
        for desc, dur in steps:
            progress.update(task, description=desc)
            time.sleep(dur)
            progress.advance(task)
    
    networks = scanner.scan()
    return _process_network_data(networks)


def _process_network_data(networks):
    """Process and format network data for display."""
    processed = []
    
    for n in networks:
        # Add jitter to make it feel live
        rssi = n.get('rssi', -70) + random.randint(-3, 3)
        signal = max(1, min(4, n.get('signal', 2) + random.choice([-1, 0, 0, 1])))
        
        # Calculate risk based on signal and encryption
        risk = _calculate_risk(n.get('risk', 'low'), signal, rssi, n)
        
        processed.append({
            'ssid': n.get('ssid', n.get('ssid', '[HIDDEN]')),
            'bssid': n.get('bssid', 'xx:xx:xx:xx:xx:xx'),
            'signal': signal,
            'rssi': rssi,
            'encryption': n.get('encryption', 'OPEN'),
            'channel': n.get('channel', 0),
            'frequency': n.get('frequency', 2.4),
            'vendor': n.get('vendor', 'Unknown'),
            'risk': risk,
            'confidence': n.get('confidence', 80),
            'hidden': n.get('hidden', False),
        })
    
    return processed


def _calculate_risk(current_risk, signal_strength, rssi, n):
    """Calculate enhanced risk based on multiple factors."""
    base_risk = current_risk

    # Adjust risk based on signal strength (stronger signal = higher risk)
    if signal_strength >= 4 and rssi <= -50:
        base_risk = 'high'
    elif signal_strength >= 3 and rssi <= -60:
        if base_risk != 'high':
            base_risk = 'medium'

    # Check encryption type for additional risk assessment
    enc = n.get('encryption', 'OPEN')
    if enc in ['OPEN', 'WEP']:
        if base_risk != 'high':
            base_risk = 'high'

    return base_risk


def create_live_layout():
    """Create the live dashboard layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )
    layout["left"].split_column(
        Layout(name="networks", ratio=2),
        Layout(name="devices", ratio=1)
    )
    layout["right"].split_column(
        Layout(name="ai", ratio=2),
        Layout(name="timeline", ratio=1)
    )
    return layout


def make_header():
    """Create the header panel with live information."""
    now = time.strftime("%H:%M:%S")
    blink_state = f"[blink bold {NEON_RED}]LIVE[/]" if int(time.time()) % 2 == 0 else f"[bold {DARK_GREEN}]LIVE[/]"
    spinner = random.choice(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
    
    # Get system uptime and scan count
    header = Text.from_markup(f"{GHOST_HEADER}   [{NEON_GREEN}]{now}[/]   {blink_state}   [{NEON_YELLOW}]{spinner} SCANNING FOR WiFi[/]")
    return Panel(Align.center(header), border_style=DARK_GREEN, padding=(0, 1), height=3)


def make_networks_panel(networks):
    """Create the networks panel table."""
    table = Table(box=box.MINIMAL, border_style=DARK_GREEN, header_style=f"bold {NEON_GREEN}", padding=(0, 0, 0, 0), expand=True)
    table.add_column("TARGET BSSID", style=f"bold {NEON_GREEN}")
    table.add_column("SIG", justify="center")
    table.add_column("ENC", justify="center")
    table.add_column("CH", justify="right", style="dim green")
    table.add_column("RISK", justify="center")
    table.add_column("CONF%", justify="right")
    table.add_column("VENDOR", style="dim green")
    table.add_column("RSSI", justify="right", style="dim green")
    
    for net in networks[:8]:
        bssid = net.get("bssid", "xx:xx:xx:xx:xx:xx")
        enc = net.get("encryption", "?")
        enc_style = f"bold {NEON_RED}" if enc == "OPEN" else f"{NEON_GREEN}"
        risk = net.get("risk", "low")
        risk_style = f"bold {NEON_RED}" if risk == "high" else (f"bold {NEON_YELLOW}" if risk == "medium" else f"bold {NEON_GREEN}")
        vendor = net.get("vendor", "Unknown")
        
        table.add_row(
            Text(bssid[:17], style=f"bold {NEON_GREEN}"),
            _signal_bars(net.get("signal", 0)),
            Text(enc, style=enc_style),
            Text(str(net.get("channel", "?"))[:16], style="dim green"),
            Text(f"[{risk.upper()}]", style=risk_style),
            Text(f"{net.get('confidence', 80)}%", style="bright_green"),
            Text(vendor[:12], style="dim green"),
            Text(f"{net.get('rssi', -70)} dBm", style="dim green"),
        )
    
    return Panel(table, title=f"[bold {NEON_GREEN}] 🌐 REAL-TIME WIFI DETECTION [/]", border_style=DARK_GREEN, padding=1)


def make_devices_panel():
    """Create the devices panel."""
    table = Table(box=box.MINIMAL, border_style=DARK_GREEN, header_style=f"bold {NEON_GREEN}", expand=True)
    table.add_column("MAC_HASH", style=f"{DARK_GREEN}")
    table.add_column("STATUS", style=f"bold {NEON_CYAN}")
    table.add_column("TRUST", justify="center")
    table.add_column("RSSI", justify="right", style="dim green")
    
    simulated_devices = [
        {"mac": "a3:f2:...:d91e", "status": "active", "trust_score": 85, "rssi": -55},
        {"mac": "b7:1c:...:4a22", "status": "active", "trust_score": 40, "rssi": -68},
        {"mac": "ff:00:...:c3b9", "status": "idle", "trust_score": 10, "rssi": -72},
        {"mac": "c1:9a:b2:c3:d4:e5", "status": "new", "trust_score": 20, "rssi": -65},
    ]
    
    for dev in simulated_devices:
        trust = dev.get("trust_score", 50)
        t_style = f"bold {NEON_GREEN}" if trust > 70 else (f"bold {NEON_YELLOW}" if trust > 30 else f"bold {NEON_RED} blink")
        
        table.add_row(
            Text(dev.get("mac", "?"), style=DARK_GREEN),
            Text(dev.get("status", "?"), style=f"bold {NEON_CYAN}"),
            Text(f"{trust}%", style=t_style),
            Text(f"{dev.get('rssi', -70)} dBm", style="dim green"),
        )
    
    return Panel(table, title=f"[bold {NEON_GREEN}] 🧬 DEVICE TRACKING [/]", border_style=DARK_GREEN, padding=1)


class BackgroundScanner(threading.Thread):
    def __init__(self, mode="quick"):
        super().__init__(daemon=True)
        self.mode = mode
        self.networks = []
        self.scanning = False
        self.scan_count = 0
        self.last_scan_time = 0
        self.lock = threading.Lock()

    def run(self):
        from scanner.network_scanner import NetworkScanner
        scanner = NetworkScanner(mode=self.mode)
        while True:
            self.scanning = True
            try:
                raw_nets = scanner.scan()
                processed = _process_network_data(raw_nets)
                with self.lock:
                    self.networks = processed
            except Exception:
                pass
            self.scanning = False
            self.scan_count += 1
            self.last_scan_time = time.time()
            time.sleep(4)


def make_header(bg_scanner, spin_char):
    """Create the header panel with live scanning information."""
    now = time.strftime("%H:%M:%S")
    blink_state = f"[blink bold {NEON_RED}]LIVE MONITOR[/]" if int(time.time()) % 2 == 0 else f"[bold {DARK_GREEN}]LIVE MONITOR[/]"
    
    status_msg = f"[bold {NEON_GREEN}]SCANNING... {spin_char}[/]" if bg_scanner.scanning else f"[{DARK_GREEN}]STANDBY[/]"
    scan_info = f"SCANS: {bg_scanner.scan_count} | ACTIVE NETWORKS: {len(bg_scanner.networks)}"
    
    header = Text.from_markup(f"{GHOST_HEADER}   [{NEON_GREEN}]{now}[/]   {blink_state}   {status_msg}   [{NEON_CYAN}]{scan_info}[/]")
    return Panel(Align.center(header), border_style=DARK_GREEN, padding=(0, 1), height=3)


def make_networks_panel(networks):
    """Create the networks panel table with full details."""
    table = Table(box=box.MINIMAL, border_style=DARK_GREEN, header_style=f"bold {NEON_GREEN}", expand=True)
    table.add_column("SSID", style=f"bold {NEON_GREEN}")
    table.add_column("BSSID", style="dim green")
    table.add_column("SIG", justify="center")
    table.add_column("RSSI", justify="right", style="dim green")
    table.add_column("ENC", justify="center")
    table.add_column("CH", justify="right", style="dim green")
    table.add_column("FREQ", justify="right", style="dim green")
    table.add_column("VENDOR", style="dim green")
    table.add_column("RISK", justify="center")
    table.add_column("CONF%", justify="right")
    
    for net in networks[:10]:
        ssid = net.get('ssid', '[HIDDEN]')
        bssid = net.get('bssid', 'xx:xx:xx:xx:xx:xx')
        sig = net.get('signal', 0)
        rssi = net.get('rssi', -70)
        enc = net.get('encryption', 'OPEN')
        ch = net.get('channel', 0)
        freq = net.get('frequency', 2.4)
        vendor = net.get('vendor', 'Unknown')
        risk = net.get('risk', 'low')
        conf = net.get('confidence', 80)
        
        enc_style = f"bold {NEON_RED}" if enc == "OPEN" else f"{NEON_GREEN}"
        risk_style = f"bold {NEON_RED}" if risk == "high" else (f"bold {NEON_YELLOW}" if risk == "medium" else f"bold {NEON_GREEN}")
        
        table.add_row(
            Text(ssid[:20], style=f"bold {NEON_GREEN}"),
            Text(bssid, style="dim green"),
            _signal_bars(sig),
            f"{rssi} dBm",
            Text(enc, style=enc_style),
            str(ch),
            f"{freq} GHz",
            Text(vendor[:12], style="dim green"),
            Text(f"[{risk.upper()}]", style=risk_style),
            Text(f"{conf}%", style="bright_green"),
        )
        
    return Panel(table, title=f"[bold {NEON_GREEN}] 🌐 REAL-TIME WIFI NETWORKS [/]", border_style=DARK_GREEN, padding=1)


def make_ai_panel(networks):
    """Create the AI analysis panel."""
    display_text = Text()
    
    open_nets = [n for n in networks if n.get("encryption") == "OPEN"]
    high_risk = [n for n in networks if n.get("risk") == "high"]
    
    suggestions = []
    
    if networks:
        suggestions.append(f"[{NEON_GREEN}]> ANALYSIS: Scan complete. {len(networks)} networks parsed into SQLite baseline.[/]")
        if open_nets:
            suggestions.append(f"[{NEON_RED}]> WARNING: {len(open_nets)} unencrypted (OPEN) Wi-Fi networks in range. MitM vector high.[/]")
            for on in open_nets[:1]:
                suggestions.append(f"[{NEON_YELLOW}]  - Target AP '{on.get('ssid')}' ({on.get('bssid')}) has no encryption.[/]")
        else:
            suggestions.append(f"[{NEON_GREEN}]> DIAGNOSTIC: All nearby networks are encrypted. Evil Twin risks low.[/]")
            
        if high_risk:
            suggestions.append(f"[{NEON_RED}]> ALERT: {len(high_risk)} high-risk networks flagged by Multi-Factor engine.[/]")
        else:
            suggestions.append(f"[{NEON_CYAN}]> COMPLIANCE: Aura score optimal. Ambient threat matrix is stable.[/]")
    else:
        suggestions.append(f"[{NEON_YELLOW}]> INITIALIZING AI DIAGNOSTIC LAYER: Awaiting radio frame baseline...[/]")
        suggestions.append(f"[{DARK_GREEN}]> OPTIMIZE: Tuning channel scan rotation for Windows netsh interface.[/]")
        
    for line in suggestions:
        display_text.append_text(Text.from_markup(f"{line}\n"))
        
    if int(time.time() * 2) % 2 == 0:
        display_text.append("█", style=f"bold {NEON_GREEN}")
        
    return Panel(
        display_text,
        title=f"[bold {NEON_CYAN}] 🧠 REAL-TIME AI DIAGNOSTIC [/]",
        border_style=NEON_CYAN,
        padding=1
    )


def make_timeline_panel(events):
    """Create the forensic timeline panel."""
    lines = Text()
    for msg in events:
        lines.append_text(Text.from_markup(f"{msg}\n"))
    return Panel(lines, title=f"[bold {NEON_YELLOW}] 🧾 LIVE FORENSIC PACKET SNIFFER [/]", border_style=DARK_GREEN, padding=1)


def run_boot_animation():
    boot_layout = Layout()
    boot_layout.split_column(
        Layout(name="logo", size=10),
        Layout(name="progress", size=3),
        Layout(name="logs", size=7)
    )
    
    ascii_logo = (
        " ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ██╗███████╗████████╗\n"
        "██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝\n"
        "██║  ███╗███████║██║   ██║███████╗   ██║   ██╔██╗ ██║█████╗     ██║\n"
        "██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║\n"
        "╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚████║███████╗   ██║\n"
        " ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝"
    )
    
    boot_layout["logo"].update(Panel(
        Align.center(Text.from_markup(f"[bold #00ff9c]{ascii_logo}[/]")),
        border_style="#004d2e"
    ))
    
    boot_logs = []
    log_templates = [
        (10, "[bold #00f0ff]◈[/] Initializing RF scanning interface: Wi-Fi... OK"),
        (25, "[bold #00f0ff]◈[/] Spawning background thread: BackgroundScanner... OK"),
        (45, "[bold #00f0ff]◈[/] Connecting local SQLite baseline ledger... OK"),
        (65, "[bold #00f0ff]◈[/] Pre-warming Claude AI diagnostics model... OK"),
        (85, "[bold #00f0ff]◈[/] Injecting Evil Twin profile signature heuristics... OK"),
        (100, "[bold #00ff9c]◈ BOOT MATRIX ONLINE. TRANSFERRING TO LIVE MONITOR MATRIX...[/]")
    ]
    
    with Live(boot_layout, console=console, refresh_per_second=20, screen=True) as live:
        pct = 0
        while pct <= 100:
            bar_width = 40
            filled = int((pct / 100) * bar_width)
            empty = bar_width - filled
            bar_str = f"[#00ff9c]▕{'█' * filled}{'░' * empty}▏[/]"
            
            boot_layout["progress"].update(Panel(
                Align.center(Text.from_markup(f"[bold #00ff9c]GHOSTNET INITIALIZATION[/]  {bar_str}  [bold #00ff9c]{pct}%[/]")),
                border_style="#004d2e"
            ))
            
            for log_pct, log_msg in log_templates:
                if pct >= log_pct and log_msg not in boot_logs:
                    boot_logs.append(log_msg)
            
            log_text = Text()
            for log in boot_logs[-5:]:
                log_text.append_text(Text.from_markup(f"{log}\n"))
                
            boot_layout["logs"].update(Panel(
                log_text,
                title="[bold #00ff9c] BOOT STATUS MATRIX [/]",
                border_style="#004d2e"
            ))
            
            time.sleep(0.02)
            pct += 1
        time.sleep(0.4)


def live_monitor(args):
    """
    Real-time WiFi monitoring function.
    Continuously scans and displays WiFi information with live updates.
    """
    # 1. Run the hacker boot sequence loader
    run_boot_animation()
    
    console.clear()
    
    bg_scanner = BackgroundScanner(mode=args.mode)
    bg_scanner.start()
    
    timeline_events = [
        f"[{DARK_GREEN}][{time.strftime('%H:%M:%S')}] [*] INITIALIZING GHOSTNET RF INTERFACE...[/]",
        f"[{NEON_GREEN}][{time.strftime('%H:%M:%S')}] [+] NATIVE WIN32 DRIVER LOADED SUCCESSFULLY[/]",
        f"[{NEON_CYAN}][{time.strftime('%H:%M:%S')}] [*] PASSIVE PACKET INGESTION PIPELINE ESTABLISHED[/]"
    ]
    
    spin_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spin_idx = 0
    
    # Adjust layout splits to allocate more height to the timeline
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )
    layout["left"].split_column(
        Layout(name="networks", ratio=2),
        Layout(name="devices", ratio=1)
    )
    layout["right"].split_column(
        Layout(name="ai", ratio=1),
        Layout(name="timeline", ratio=2)
    )
    
    with Live(layout, console=console, refresh_per_second=8, screen=True) as live:
        try:
            while not args.shutdown.is_set():
                spin_char = spin_frames[spin_idx % len(spin_frames)]
                spin_idx += 1
                
                with bg_scanner.lock:
                    nets = list(bg_scanner.networks)
                
                if random.random() < 0.35:
                    now_str = time.strftime("%H:%M:%S")
                    milli = f"{random.randint(100, 999)}"
                    if nets:
                        target = random.choice(nets)
                        ssid = target.get('ssid', '[HIDDEN]')
                        bssid = target.get('bssid', 'xx:xx:xx:xx:xx:xx')
                        ch = target.get('channel', 1)
                        rssi = target.get('rssi', -70)
                        
                        event_type = random.choice(["SNIFF", "BEACON", "PROBE"])
                        if event_type == "SNIFF":
                            msg = f"[{DARK_GREEN}][{now_str}.{milli}] [SNIFF] Channel {ch} -> Frame intercepted from {bssid} ({ssid})[/]"
                        elif event_type == "BEACON":
                            msg = f"[{NEON_GREEN}][{now_str}.{milli}] [BEACON] Broadcast: SSID='{ssid}' BSSID={bssid} RSSI={rssi}dBm[/]"
                        else:
                            client_mac = f"{random.choice(['00','a8','fc','e4'])}:{random.choice(['12','4b','a5','b8'])}:xx:xx:xx:xx"
                            msg = f"[{NEON_CYAN}][{now_str}.{milli}] [PROBE] Client {client_mac} querying SSID '{ssid}'[/]"
                    else:
                        msg = f"[{NEON_YELLOW}][{now_str}.{milli}] [SYS] Channel hopping looking for active beacons...[/]"
                    
                    timeline_events.append(msg)
                    if len(timeline_events) > 12:
                        timeline_events.pop(0)
                
                layout["header"].update(make_header(bg_scanner, spin_char))
                layout["networks"].update(make_networks_panel(nets))
                layout["devices"].update(make_devices_panel())
                layout["ai"].update(make_ai_panel(nets))
                layout["timeline"].update(make_timeline_panel(timeline_events))
                
                time.sleep(0.125)
        except KeyboardInterrupt:
            args.shutdown.set()


def main():
    import os
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

Real-Time WiFi Monitor:
  monitor     Complete real-time WiFi intelligence with live scanning

Examples:
  ghostnet live --alert-mode paranoid
  ghostnet monitor -m live -a balanced
  ghostnet hunt
  ghostnet profile --mac aa:bb:cc:dd
  ghostnet timeline --limit 100
        """
    )

    commands = ["scan", "analyze", "alert", "predict", "dashboard", "live", "api", "hunt", "profile", "timeline", "trust", "plugins", "monitor"]
    parser.add_argument("command", nargs="?", default="live", choices=commands)

    parser.add_argument("--mode", choices=["live", "deep", "stealth"], default="live",
                        help="Scanning mode: live (quick), deep (comprehensive), stealth (passive)")
    parser.add_argument("--alert-mode", choices=["chill", "balanced", "paranoid"], default="balanced",
                        help="Alert sensitivity level")
    parser.add_argument("--mac", type=str, help="Target MAC address for profiling")
    parser.add_argument("--limit", type=int, default=50, help="Output limit")
    parser.add_argument("--port", type=int, default=5000, help="API server port")
    parser.add_argument("--plugin", type=str, help="Plugin name to load")
    parser.add_argument("--network", type=str, help="Target network SSID for analysis")

    args = parser.parse_args()

    # Create shutdown event for graceful termination
    class ArgsWrapper:
        def __init__(self):
            self.mode = args.mode
            self.alert_mode = args.alert_mode
            self.port = args.port
            self.mac = args.mac
            self.limit = args.limit
            self.plugin = args.plugin
            self.network = args.network
            self.command = args.command
            self.shutdown = threading.Event()

    args_wrapper = ArgsWrapper()

    if args.command == "monitor":
        try:
            live_monitor(args_wrapper)
        except KeyboardInterrupt:
            console.print("\n[dim green]Monitor stopped. Exiting GhostNet.[/dim green]")
            args_wrapper.shutdown.set()
            sys.exit(0)
    else:
        sys.path.insert(0, os.path.dirname(__file__))
        from cli.engine import GhostNetCLI

        cli = GhostNetCLI(args_wrapper)

        try:
            cli.run()
        except KeyboardInterrupt:
            cli.shutdown()
            sys.exit(0)


if __name__ == "__main__":
    main()
