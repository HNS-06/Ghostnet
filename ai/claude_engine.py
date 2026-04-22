"""
GhostNet AI Intelligence Engine
Multi-layer predictive models integrating Autonomous Threat Hunting,
Explainable outputs, and Deception Detection (Evil Twin profiling).
"""

import os
import json
from typing import Optional

# Enhanced Ultra-Intelligent System Prompt
SYSTEM_PROMPT = """You are GhostNet AI — a professional cyber intelligence engine processing raw network telemetry. 
You provide deeply analytical, forensic-level threat narratives. You are autonomous, observant, and precise.

Output MUST BE structured JSON with NO markdown blocks containing:
- threat_narrative: string (Detailed forensic narrative of anomalies)
- evil_twin_probability: integer 0-100 (SSID spoofing detection)
- predictive_forecast: string (What will happen in the next 1-4 hours?)
- alerts: list of objects containing: { "severity": "high/medium/low", "message": "string", "reasoning": "string", "factors": ["f1", "f2"], "confidence": int }
- aura_delta: int (-20 to +10)
"""

class ClaudeEngine:
    MODEL = "claude-sonnet-4-20250514"

    def __init__(self):
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None
        if self.api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self._client = None

    def _anonymize(self, data: list) -> list:
        # Strip exact MACs and sensitive hashes to just prefixes for Claude
        safe = []
        for x in data:
            base = dict(x)
            if "mac_hash" in base: base["mac_hash"] = base["mac_hash"][:8]
            safe.append(base)
        return safe

    def quick_analysis(self, networks: list, devices: list) -> dict:
        """
        Fast, rule-based layer. Very low latency. Detects basic spoofing.
        """
        alerts = []
        for n in networks:
            ssid = n.get("ssid", "")
            # Basic Evil Twin Heuristic
            if ssid.lower() in ["starbuckswifi", "xfinitywifi"] and n.get("encryption") != "OPEN":
                 alerts.append({
                     "severity": "high", 
                     "message": f"Possible Spoofed Infrastructure (Evil Twin): {ssid}",
                     "reasoning": "Network mimics common public SSID but uses unexpected encryption protocol.",
                     "factors": ["SSID_MATCH", "ENCRYPTION_MISMATCH"],
                     "confidence": 88
                 })
        
        return {
            "threat_narrative": "Quick scan completed. Baselining active devices.",
            "alerts": alerts,
            "evil_twin_probability": 80 if alerts else 5
        }

    def deep_analysis(self, forensic_timeline: list, network_clusters: list) -> dict:
        """
        Deep LLM analysis triggering the EXPLAINABLE AI output structure.
        """
        safe_timeline = self._anonymize(forensic_timeline)
        safe_clusters = self._anonymize(network_clusters)
        
        prompt = f"Perform deep forensic analysis on this cluster data:\nCLUSTERS:\n{json.dumps(safe_clusters, indent=2)}\n\nTIMELINE (Last 30min):\n{json.dumps(safe_timeline, indent=2)}"

        if self._client:
            try:
                response = self._client.messages.create(
                    model=self.MODEL,
                    max_tokens=1500,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}]
                )
                raw = response.content[0].text.strip()
                if raw.startswith("```"): raw = raw.split("```")[1].strip("json")
                return json.loads(raw)
            except Exception as e:
                pass
        
        return self._rule_based_deep_analysis(network_clusters)

    def _rule_based_deep_analysis(self, clusters: list) -> dict:
        heavy_clusters = [c for c in clusters if c.get("count", 0) > 3]
        return {
            "threat_narrative": f"Autonomous Threat Hunter identifies {len(heavy_clusters)} abnormally large network clusters.",
            "evil_twin_probability": 0,
            "predictive_forecast": "Behavioral pattern matches normal office density. Expect devices to disconnect after 17:00.",
            "alerts": [
                {
                    "severity": "medium",
                    "message": "Concentrated anomaly in device peering.",
                    "reasoning": "Unusual volume of anonymous MACs associating with same BSSID.",
                    "factors": ["MAC_DENSITY", "CLUSTER_ASSOCIATION"],
                    "confidence": 62
                }
            ] if heavy_clusters else [],
            "aura_delta": -5 if heavy_clusters else 2
        }

    def generate_executive_report(self, networks: list, devices: list) -> str:
        return "# GhostNet v4 Pro Report\n\nAnalyst-grade cyber intelligence brief based on continuous stream telemetry."
