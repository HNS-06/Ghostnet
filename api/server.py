"""
GhostNet REST API
Flask-powered endpoints for network data, devices, alerts, and AI analysis.
"""

from flask import Flask, jsonify, request
from functools import wraps
import time

app = Flask(__name__)

# Simple in-memory rate limiter
_last_requests = {}
RATE_LIMIT_S = 1  # 1 request/second per endpoint

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response



def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = f.__name__
        now = time.time()
        if now - _last_requests.get(key, 0) < RATE_LIMIT_S:
            return jsonify({"error": "rate_limited", "retry_after": RATE_LIMIT_S}), 429
        _last_requests[key] = now
        return f(*args, **kwargs)
    return wrapper


def _db():
    from database.db import GhostDB
    return GhostDB()


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "GhostNet API",
        "version": "2.4.1",
        "endpoints": ["/networks", "/devices", "/alerts", "/aura", "/analyze", "/predict", "/stats"],
    })


@app.route("/networks", methods=["GET"])
@rate_limited
def get_networks():
    """
    GET /networks
    Query params:
      risk=low|medium|high   Filter by risk level
      enc=OPEN|WPA2|WPA3     Filter by encryption
      limit=N                Max results (default 50)
    """
    db = _db()
    nets = db.get_recent_networks(limit=int(request.args.get("limit", 50)))
    risk_filter = request.args.get("risk")
    enc_filter = request.args.get("enc")
    if risk_filter:
        nets = [n for n in nets if n.get("risk") == risk_filter]
    if enc_filter:
        nets = [n for n in nets if n.get("encryption", "").upper() == enc_filter.upper()]
    return jsonify({"count": len(nets), "networks": nets})


@app.route("/devices", methods=["GET"])
@rate_limited
def get_devices():
    """GET /devices — tracked devices with hashed MACs"""
    db = _db()
    devs = db.get_recent_devices()
    return jsonify({"count": len(devs), "devices": devs})


@app.route("/alerts", methods=["GET"])
@rate_limited
def get_alerts():
    """
    GET /alerts
    Query params:
      unread=true   Only unacknowledged alerts
      severity=high|medium|low
    """
    db = _db()
    unread = request.args.get("unread", "false").lower() == "true"
    alerts = db.get_alerts(unacknowledged_only=unread)
    sev = request.args.get("severity")
    if sev:
        alerts = [a for a in alerts if a.get("severity") == sev]
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/alerts/<int:alert_id>/ack", methods=["POST"])
def ack_alert(alert_id):
    """POST /alerts/:id/ack — acknowledge an alert"""
    db = _db()
    db.acknowledge_alert(alert_id)
    return jsonify({"acknowledged": True, "id": alert_id})


@app.route("/aura", methods=["GET"])
@rate_limited
def get_aura():
    """GET /aura — Digital Aura Score and history"""
    db = _db()
    history = db.get_aura_history(days=7)
    nets = db.get_recent_networks(limit=20)
    devs = db.get_recent_devices(limit=20)
    from scanner.risk_engine import RiskEngine
    score = RiskEngine().compute_aura_score(nets, devs)
    return jsonify({
        "aura_score": score,
        "breakdown": {"privacy": 88, "exposure": 61, "threat": 27},
        "history": history,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    """POST /analyze — trigger AI analysis via Claude"""
    db = _db()
    nets = db.get_recent_networks()
    from ai.claude_engine import ClaudeEngine
    engine = ClaudeEngine()
    result = engine.analyze(nets)
    return jsonify(result)


@app.route("/predict", methods=["GET"])
def predict():
    """GET /predict?hours=4 — risk forecast"""
    hours = int(request.args.get("hours", 4))
    from ai.claude_engine import ClaudeEngine
    result = ClaudeEngine().predict(hours=hours)
    return jsonify(result)

@app.route("/export_report", methods=["GET"])
def export_report():
    """GET /export_report — Generates a markdown executive summary."""
    db = _db()
    nets = db.get_recent_networks()
    from ai.claude_engine import ClaudeEngine
    report = ClaudeEngine().generate_executive_report(nets)
    return jsonify({"report": report})


@app.route("/stats", methods=["GET"])
def stats():
    """GET /stats — database statistics"""
    db = _db()
    return jsonify(db.stats())


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not_found", "message": str(e)}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "server_error", "message": str(e)}), 500


def run_api(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    app.run(host=host, port=port, debug=debug)
