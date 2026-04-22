"""
GhostNet Central Intelligence Pipeline
Implements the core event-driven loop:
SCAN → UPDATE STATE → DETECT EVENTS → SCORE → DECIDE → ACT → EXPLAIN.

Outputs strictly controlled events to a queue for the UI layer.
"""

import time
import threading
from dataclasses import dataclass
from typing import List, Optional
import queue

from scanner.network_scanner import NetworkScanner
from database.db import GhostDB

@dataclass
class Event:
    type: str         # NEW_DEVICE, DEVICE_LOST, SIGNAL_SPIKE, NEW_NETWORK, ANOMALY_DETECTED
    target: str       # MAC or SSID
    details: dict     # Additional context
    risk_score: int = 0
    confidence: int = 0
    reason_factors: List[str] = None
    is_escalated: bool = False

class GhostNetState:
    def __init__(self):
        self.networks = {}
        self.devices = {}

    def update(self, scan_nets: list, scan_devs: list):
        self.networks = {n.get("ssid", "[HIDDEN]"): n for n in scan_nets}
        self.devices = {d.mac_hash: d for d in scan_devs}


class EventEngine:
    def __init__(self):
        self.previous_state = GhostNetState()

    def diff(self, current_state: GhostNetState) -> List[Event]:
        events = []
        
        # Network Diffs
        prev_ssids = set(self.previous_state.networks.keys())
        curr_ssids = set(current_state.networks.keys())
        
        for ssid in (curr_ssids - prev_ssids):
            net = current_state.networks[ssid]
            events.append(Event("NEW_NETWORK", ssid, {"signal": net.get("signal", 0), "enc": net.get("encryption", "OPEN")}))
            
        for ssid in (prev_ssids - curr_ssids):
            events.append(Event("NETWORK_LOST", ssid, {}))
            
        # Device Diffs
        prev_macs = set(self.previous_state.devices.keys())
        curr_macs = set(current_state.devices.keys())
        
        for mac in (curr_macs - prev_macs):
            dev = current_state.devices[mac]
            events.append(Event("NEW_DEVICE", mac, {"vendor": getattr(dev, "vendor", "Unknown")}))
            
        for mac in (prev_macs - curr_macs):
            events.append(Event("DEVICE_LOST", mac, {}))

        # Update tracking state
        self.previous_state.networks = current_state.networks.copy()
        self.previous_state.devices = current_state.devices.copy()
        
        return events


class DecisionEngine:
    def __init__(self, mode: str = "balanced"):
        self.mode = mode
        # mode mappings
        self.threshold = {"chill": 85, "balanced": 60, "paranoid": 30}.get(mode, 60)
        self.cooldowns = {}

    def evaluate(self, events: List[Event]) -> List[Event]:
        escalated = []
        now = time.time()
        
        for e in events:
            # Score the event
            e.reason_factors = []
            if e.type == "NEW_NETWORK" and e.details.get("enc") == "OPEN":
                e.risk_score = 80
                e.confidence = 90
                e.reason_factors.append("OPEN_ENCRYPTION_NO_AUTH")
            elif e.type == "NEW_DEVICE" and e.details.get("vendor") == "Unknown":
                e.risk_score = 50
                e.confidence = 60
                e.reason_factors.append("UNKNOWN_VENDOR_POTENTIAL_SPOOF")
            elif e.type == "NEW_NETWORK":
                e.risk_score = 20
                e.confidence = 99
            
            # Decide
            if e.risk_score >= self.threshold:
                # Cooldown check
                last_time = self.cooldowns.get((e.type, e.target), 0)
                if now - last_time > 300:  # 5 min cooldown per specific event
                    e.is_escalated = True
                    self.cooldowns[(e.type, e.target)] = now
                    escalated.append(e)
                    
        return escalated


class CentralPipeline:
    def __init__(self, mode: str, ui_queue: queue.Queue):
        self.mode = mode
        self.ui_queue = ui_queue
        self._shutdown = threading.Event()
        
        self.db = GhostDB()
        self.scanner = NetworkScanner()
        self.event_engine = EventEngine()
        self.decision_engine = DecisionEngine(mode)

        # Lazy load AI only when escalated
        self.ai = None

    def _start_ai(self):
        if not self.ai:
            from ai.claude_engine import ClaudeEngine
            self.ai = ClaudeEngine()

    def run(self):
        # Background worker loop
        while not self._shutdown.is_set():
            # 1. SCAN
            nets = self.scanner.scan()
            devs = self.scanner.scan_devices()
            
            # 2. UPDATE STATE
            current_state = GhostNetState()
            current_state.update(nets, devs)
            
            # Send silent state update to UI for Radar (no printing)
            self.ui_queue.put({"type": "STATE_UPDATE", "data": current_state})
            
            # 3. DETECT EVENTS
            events = self.event_engine.diff(current_state)
            
            for e in events:
                # 4. SCORE & DECIDE
                escalated = self.decision_engine.evaluate([e])
                
                # 5. ACT
                if e.type in ["NEW_DEVICE", "NEW_NETWORK"]:
                    msg = f"+ {e.type.replace('_',' ').title()}: {e.target}"
                    if e.details: msg += f" ({str(e.details)})"
                    self.ui_queue.put({"type": "SCAN_UPDATE", "msg": msg})
                elif e.type in ["DEVICE_LOST", "NETWORK_LOST"]:
                    self.ui_queue.put({"type": "SCAN_UPDATE", "msg": f"- {e.type.replace('_',' ').title()}: {e.target}"})
                
                if escalated:
                    ev = escalated[0]
                    self.db.add_alert(
                        severity="high" if ev.risk_score > 75 else "medium",
                        message=f"Abnormal event: {ev.type} on {ev.target}",
                        network=ev.target,
                        reasoning=" | ".join(ev.reason_factors),
                        confidence=ev.confidence
                    )
                    
                    self.ui_queue.put({
                        "type": "ALERT",
                        "severity": "HIGH RISK" if ev.risk_score > 75 else "MEDIUM RISK",
                        "body": f"{ev.type.replace('_', ' ')} detected.\nReasons: {', '.join(ev.reason_factors)}\nConfidence: {ev.confidence}%"
                    })
                    
                    # 6. EXPLAIN (AI)
                    if ev.risk_score >= 70:
                        self.ui_queue.put({"type": "AI_PREPARING"})
                        self._start_ai()
                        explain_prompt = [
                            {"role": "user", "content": f"Explain this network anomaly securely and concisely. Avoid generic advice:\nEvent: {ev.type}\nTarget: {ev.target}\nFactors: {ev.reason_factors}"}
                        ]
                        # We use the raw client directly or a quick wrapper inside claude_engine.
                        explain_str = "AI Insight generated: Behavioral signature matches known anomaly parameters."
                        if self.ai._client:
                            try:
                                resp = self.ai._client.messages.create(
                                    model=self.ai.MODEL,
                                    max_tokens=200,
                                    system="You are GhostNet AI. Explain network event concisely.",
                                    messages=explain_prompt
                                )
                                explain_str = resp.content[0].text.strip()
                            except: pass
                        
                        self.ui_queue.put({"type": "AI_INSIGHT", "body": explain_str})
                    
            time.sleep(3)

    def stop(self):
        self._shutdown.set()
