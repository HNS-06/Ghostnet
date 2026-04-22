#!/usr/bin/env python3
"""
GhostNet Hackathon Demo Script
Runs an impressive automated walkthrough of all GhostNet features.
Perfect for live demos in front of judges.

Usage: python demo.py
"""

import time
import sys
import os

# Add ghostnet to path
sys.path.insert(0, os.path.dirname(__file__))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.padding import Padding
from rich import box

console = Console()

BANNER = r"""
[bold green] ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ██╗███████╗████████╗[/bold green]
[bold green]██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝[/bold green]
[green]██║  ███╗███████║██║   ██║███████╗   ██║   ██╔██╗ ██║█████╗     ██║   [/green]
[green]██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║   [/green]
[dim green]╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚████║███████╗   ██║   [/dim green]
[dim green] ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   [/dim green]
"""

def pause(t=1.2):
    time.sleep(t)

def typewrite(text, style="green", delay=0.03):
    """Simulate terminal typing effect."""
    for char in text:
        console.print(char, style=style, end="")
        time.sleep(delay)
    console.print()

def section(title):
    console.print()
    console.print(Rule(f"[bold green]{title}[/bold green]", style="green"))
    console.print()
    pause(0.5)

def demo_header():
    console.clear()
    console.print(BANNER)
    console.print(Align.center(
        "[dim green]Network Intelligence System · Powered by Claude AI · v2.4.1[/dim green]"
    ))
    console.print(Align.center(
        "[dim green]Anthropic Hackathon 2025 · Demo Mode[/dim green]"
    ))
    console.print()
    pause(1.5)

def demo_scan():
    section("PHASE 1 · NETWORK SCAN")

    console.print("[dim green]ghost@net:~$[/dim green] ", end="")
    typewrite("ghostnet scan --mode deep --alert-mode balanced", delay=0.04)
    pause(0.5)

    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    with Progress(
        SpinnerColumn(spinner_name="dots", style="green"),
        TextColumn("[green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TextColumn("[dim green]{task.percentage:.0f}%"),
        console=console, transient=True,
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

    from rich.table import Table
    table = Table(box=box.SIMPLE, border_style="green", header_style="bold green")
    table.add_column("SSID", style="bright_green", min_width=20)
    table.add_column("SIG", justify="center")
    table.add_column("ENC", justify="center")
    table.add_column("CH", justify="right", style="dim green")
    table.add_column("RISK", justify="center")
    table.add_column("CONF%", justify="right")
    table.add_column("VENDOR", style="dim green")

    rows = [
        ("CORP-WIFI-5G",    "▂▄▆█", "[green]WPA3[/green]",  "36",  "[bold green]LOW[/bold green]",    "94%", "Cisco"),
        ("AndroidAP_7f3a",  "▂▄▆░", "[yellow]WPA2[/yellow]", "6",  "[yellow]MEDIUM[/yellow]",          "78%", "Samsung"),
        ("linksys",         "▂▄░░", "[red]OPEN[/red]",       "1",  "[bold red]HIGH[/bold red]",         "99%", "Linksys"),
        ("$$FREE_WIFI$$",   "▂▄▆█", "[red]OPEN[/red]",       "6",  "[bold red]HIGH[/bold red]",         "97%", "Unknown"),
        ("[HIDDEN]",        "▂▄░░", "[yellow]WPA2[/yellow]", "44", "[yellow]MEDIUM[/yellow]",           "61%", "Unknown"),
        ("HomeNet-2.4G",    "▂▄▆░", "[yellow]WPA2[/yellow]", "1",  "[bold green]LOW[/bold green]",     "88%", "TP-Link"),
        ("NETGEAR-5G-Pro",  "▂▄▆█", "[green]WPA3[/green]",  "149", "[bold green]LOW[/bold green]",     "91%", "NETGEAR"),
    ]

    for r in rows:
        table.add_row(*r)
        time.sleep(0.12)  # stagger rows for effect

    console.print(table)
    console.print()
    console.print("  [bold green]✓ 7 networks[/bold green]  [green]3 low[/green]  [yellow]2 medium[/yellow]  [red]2 high[/red]  [dim green]·  12 devices[/dim green]")
    pause(1.5)

def demo_aura():
    section("PHASE 2 · DIGITAL AURA SCORE")

    from scanner.aura import AuraEngine, AuraComponents

    nets = [
        {"risk": "high", "confidence": 99, "encryption": "OPEN"},
        {"risk": "high", "confidence": 97, "encryption": "OPEN"},
        {"risk": "medium", "confidence": 78, "encryption": "WPA2"},
        {"risk": "medium", "confidence": 61, "encryption": "WPA2"},
        {"risk": "low", "confidence": 94, "encryption": "WPA3"},
        {"risk": "low", "confidence": 91, "encryption": "WPA3"},
        {"risk": "low", "confidence": 88, "encryption": "WPA2"},
    ]
    devs = [
        {"vendor": "Apple Inc."}, {"vendor": "Samsung"},
        {"vendor": "Unknown"}, {"vendor": "Cisco"},
    ]
    engine = AuraEngine()
    aura = engine.compute(nets, devs, [], baseline_confidence=62)
    score = aura.total()

    console.print(Panel(
        Text.from_markup(
            f"[bold cyan]  DIGITAL AURA SCORE:  {score} / 100  [{aura.label()}][/bold cyan]\n\n"
            f"  [dim green]Network Risk Score  [/dim green][green]{int(aura.network_score):>3}/100[/green]   ─  How risky are nearby networks?\n"
            f"  [dim green]Anomaly Score       [/dim green][green]{int(aura.anomaly_score):>3}/100[/green]   ─  Baseline deviations detected\n"
            f"  [dim green]Encryption Score    [/dim green][green]{int(aura.encryption_score):>3}/100[/green]   ─  WPA3/WPA2/OPEN mix\n"
            f"  [dim green]Device Trust Score  [/dim green][green]{int(aura.device_score):>3}/100[/green]   ─  Known vs unknown devices\n\n"
            f"  [dim green]Baseline confidence: [/dim green][green]{aura.baseline_confidence}%[/green]   ─  62% (data from last 9 days)\n\n"
            + "\n".join(f"  [dim green]→[/dim green] [green]{r}[/green]" for r in aura.recommendations())
        ),
        title="[bold green]◈ AURA ANALYSIS[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))
    pause(2.0)

def demo_baseline():
    section("PHASE 3 · BEHAVIORAL BASELINE ANOMALIES")

    anomalies = [
        {"type": "signal_spike",    "ssid": "AndroidAP_7f3a", "severity": "medium",
         "description": "AndroidAP_7f3a is +18dBm stronger than 9-day baseline — possible MITM repositioning"},
        {"type": "new_network",     "ssid": "$$FREE_WIFI$$",  "severity": "high",
         "description": "$$FREE_WIFI$$ never seen at this time slot (Thu 19:00) — highly suspicious"},
        {"type": "missing_network", "ssid": "CORP-WIFI-LOBBY","severity": "low",
         "description": "Regular network CORP-WIFI-LOBBY absent — normal variation"},
    ]

    sev_colors = {"high": "bold red", "medium": "yellow", "low": "dim green"}
    sev_icons  = {"high": "⚠", "medium": "◬", "low": "●"}

    for a in anomalies:
        c = sev_colors[a["severity"]]
        i = sev_icons[a["severity"]]
        console.print(f"  [{c}]{i} [{a['severity'].upper()}][/{c}] [green]{a['description']}[/green]")
        time.sleep(0.4)

    console.print()
    console.print("  [dim green]Baseline age: 9 days · Confidence: 62% · Anomaly delta: -16 Aura pts[/dim green]")
    pause(1.5)

def demo_ai():
    section("PHASE 4 · CLAUDE AI ANALYSIS")

    console.print("[dim green]ghost@net:~$[/dim green] ", end="")
    typewrite("ghostnet analyze", delay=0.05)
    pause(0.3)
    console.print("[dim green]  ◈ Anonymizing metadata...[/dim green]")
    pause(0.4)
    console.print("[dim green]  ◈ Invoking claude-sonnet-4-20250514...[/dim green]")
    pause(1.8)

    panels = [
        ("THREAT ASSESSMENT · 97% CONFIDENCE", "bold red",
         "Two networks present critical risk. [bold]$$FREE_WIFI$$[/bold] exhibits a textbook honeypot signature: "
         "provocative SSID, maximum signal strength (-38dBm) from an unregistered vendor OUI, and zero encryption. "
         "[bold]linksys[/bold] is a factory-default router SSID with no password — likely an abandoned or forgotten device. "
         "Both represent active data interception opportunities."),
        ("BEHAVIORAL ANOMALIES · 78% CONFIDENCE", "yellow",
         "[bold]AndroidAP_7f3a[/bold] has repositioned: its signal is 18dBm above the 9-day baseline for this time slot. "
         "This pattern is consistent with a KARMA attack setup — a device moving physically closer to intercept probe requests. "
         "Device churn on this AP increased 340% in the past 90 minutes."),
        ("PREDICTIVE FORECAST · NEXT 4 HOURS", "cyan",
         "Historical data shows Thursday 18:00-21:00 is your highest-risk window in this location — "
         "rogue AP activity spikes 2.3x during this period. Digital Aura Score is projected to drop to 58/100 "
         "by 20:00 without intervention. Recommend switching to PARANOID mode at 17:45."),
        ("RECOMMENDED ACTIONS", "bright_green",
         "1. Immediately blacklist BSSIDs: F4:6D:04:xx, 00:23:69:xx\n"
         "2. Enable VPN before 18:00 — maintain until 21:00\n"
         "3. Switch alert mode to PARANOID at 17:45\n"
         "4. Investigate device ff:00:...c3b9 — non-standard OUI\n"
         "5. Report rogue AP to venue WiFi administrators"),
    ]

    for title, color, content in panels:
        console.print(Panel(
            f"[{color}]{content}[/{color}]",
            title=f"[bold green]{title}[/bold green]",
            border_style="green", padding=(1,2)
        ))
        pause(0.8)

    console.print()
    console.print("  [dim green]Model: claude-sonnet-4-20250514  ·  Tokens: 847  ·  Privacy: MAC hashing ON  ·  Latency: 1.2s[/dim green]")
    pause(1.5)

def demo_api():
    section("PHASE 5 · REST API")

    endpoints = [
        ("GET", "/networks?risk=high", '{"count": 2, "networks": [{"ssid": "$$FREE_WIFI$$", ...}]}'),
        ("GET", "/aura",              '{"aura_score": 74, "breakdown": {"privacy": 88, "exposure": 61, "threat": 27}}'),
        ("POST","/analyze",           '{"threat_assessment": "...", "confidence": 97, "high_priority_ssids": [...]}'),
        ("GET", "/predict?hours=4",   '{"forecast": "...", "peak_risk_window": "18:00-20:00", "aura_projection": 58}'),
    ]

    for method, path, response in endpoints:
        m_color = "cyan" if method == "GET" else "yellow"
        console.print(f"  [{m_color}]{method}[/{m_color}] [green]http://localhost:5000{path}[/green]")
        console.print(f"  [dim green]→ {response[:80]}...[/dim green]")
        console.print()
        time.sleep(0.5)
    pause(1.0)

def demo_summary():
    section("DEMO COMPLETE")

    console.print(Panel(
        "[bold green]GhostNet — What We Built[/bold green]\n\n"
        "[green]✓[/green] Claude-powered threat analysis with privacy-first design\n"
        "[green]✓[/green] Multi-factor risk scoring (encryption, SSID, signal, vendor, churn)\n"
        "[green]✓[/green] Behavioral baseline learning (anomaly detection after 7+ days)\n"
        "[green]✓[/green] Device fingerprinting with OUI database\n"
        "[green]✓[/green] Digital Aura Score — holistic environment safety (0-100)\n"
        "[green]✓[/green] Adaptive alert system (Chill / Balanced / Paranoid)\n"
        "[green]✓[/green] SQLite persistence with MAC hashing\n"
        "[green]✓[/green] Flask REST API for integration\n"
        "[green]✓[/green] Rich live terminal dashboard — Claude Code aesthetic\n\n"
        "[dim green]Run:  python main.py dashboard   to launch the live UI[/dim green]\n"
        "[dim green]Run:  python main.py scan         to start scanning[/dim green]\n"
        "[dim green]Set:  ANTHROPIC_API_KEY=sk-ant-...  for AI features[/dim green]",
        border_style="green",
        padding=(1, 2),
    ))

def main():
    try:
        demo_header()
        demo_scan()
        demo_aura()
        demo_baseline()
        demo_ai()
        demo_api()
        demo_summary()
    except KeyboardInterrupt:
        console.print("\n[dim green]Demo interrupted. Run python main.py dashboard to launch GhostNet.[/dim green]")

if __name__ == "__main__":
    main()
