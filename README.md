<<<<<<< HEAD
# Ghostnet
=======
# 👻 GhostNet
### AI-Powered Network Intelligence System · Anthropic Hackathon 2025

```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ██╗███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔██╗ ██║█████╗     ██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚████║███████╗   ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

> **"See what others can't. Stay ghost."**

GhostNet is a terminal-based AI-powered network intelligence system that scans nearby WiFi networks, fingerprints devices, scores threats in real time, and uses Claude AI to provide human-readable threat reasoning and predictive risk forecasting — all while keeping your data private.

---

## ✨ Why GhostNet Wins

| Feature | Description |
|---|---|
| 🧠 **Claude AI Engine** | Real-time threat analysis, behavioral reasoning, 4-hour risk predictions |
| 🔐 **Privacy-First** | No packet inspection, MAC hashing, local processing, optional AI |
| 🖥️ **Claude Code Aesthetic** | Green terminal UI built with Rich — feels like a professional tool |
| 📊 **Digital Aura Score** | Composite environment safety score (0-100) with historical tracking |
| ⚡ **Multi-Factor Risk Scoring** | Encryption, SSID patterns, signal anomalies, vendor trust, device churn |
| 🎯 **Adaptive Alerts** | Chill / Balanced / Paranoid modes |
| 🌐 **REST API** | Full JSON API for integration with dashboards and scripts |
| 💾 **SQLite Database** | Persistent network/device history and behavioral baseline |

---

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/you/ghostnet
cd ghostnet
pip install -r requirements.txt

# Set your Claude API key
export ANTHROPIC_API_KEY=sk-ant-...

# Launch live dashboard
python main.py dashboard

# Quick scan
python main.py scan

# Deep scan with AI analysis
python main.py scan --mode deep

# AI-powered threat analysis
python main.py analyze

# 4-hour predictive forecast
python main.py predict --hours 4

# REST API server
python main.py api --port 5000
```

---

## 🏗️ Architecture

```
ghostnet/
├── main.py                 Entry point + argparse CLI
├── cli/
│   ├── engine.py           Command dispatcher + Rich UI
│   └── dashboard.py        Live terminal dashboard (Rich Live)
├── scanner/
│   ├── network_scanner.py  WiFi scanning (scapy/nmap/simulated)
│   └── risk_engine.py      Multi-factor risk scoring
├── ai/
│   └── claude_engine.py    Claude API integration + fallback
├── database/
│   └── db.py               SQLite persistence layer
├── api/
│   └── server.py           Flask REST API
└── utils/
    └── privacy.py          MAC hashing, data anonymization
```

### Data Flow

```
Scan → Risk Score → Store (SQLite) → Anonymize → Claude AI → Alert → Display
```

---

## 🤖 Claude AI Integration

GhostNet uses `claude-sonnet-4-20250514` for:

1. **Threat Assessment** — Analyzes network metadata and identifies real threats vs. noise
2. **Behavioral Anomalies** — Detects unusual signal patterns, device churn, MITM positioning
3. **Predictive Forecast** — Predicts risk levels over the next N hours using temporal patterns
4. **Recommendations** — Actionable, prioritized security steps

**Privacy guarantee:** Only anonymized metadata is sent to Claude. No raw MACs, no packet contents, no personal data.

```python
# Example Claude API call in GhostNet
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    system=SYSTEM_PROMPT,
    messages=[{"role": "user", "content": anonymized_network_data}]
)
```

---

## 🔐 Privacy Architecture

- **No packet inspection** — GhostNet never reads packet payloads
- **MAC hashing** — All device identifiers are SHA-256 hashed before storage
- **Local processing first** — Risk scoring runs entirely on-device
- **Optional AI** — Run `--no-ai` for fully offline operation
- **Minimal metadata** — Only SSID, encryption type, channel, signal strength sent to Claude

---

## 📡 REST API

```
GET  /networks           List detected networks (filter by risk, enc)
GET  /devices            List tracked devices (hashed MACs)
GET  /alerts             Active alerts (filter by severity)
POST /alerts/:id/ack     Acknowledge an alert
GET  /aura               Digital Aura Score + history
POST /analyze            Trigger Claude AI analysis
GET  /predict?hours=4    Risk forecast
GET  /stats              Database statistics
```

---

## 🎨 Terminal UI Design

GhostNet's aesthetic is inspired by Claude Code:

- **Green monospace** — JetBrains Mono / Share Tech Mono
- **Rich Live layouts** — Real-time panels without flicker
- **Signal bars** — `▂▄▆█` Unicode block characters
- **CRT scanline effect** — Subtle phosphor glow aesthetic
- **Color-coded risk** — `✓ GREEN` / `◬ YELLOW` / `⚠ RED`

---

## 🏆 Hackathon Highlights

- Built on Claude AI for genuine intelligence, not just rule-based alerts
- Privacy-first design that respects user data
- Professional terminal UX that rivals commercial tools
- Fully working demo without requiring root/hardware (simulation mode)
- Extensible architecture: add new scanners, AI prompts, or API endpoints

---

## 📄 License

MIT License. Built for the Anthropic Hackathon 2025.

---

*"The best security tool is one you actually use."*
>>>>>>> b31021d (Initial Commit)
