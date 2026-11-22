"""
app.py
------
Flask REST API for the Phishing Detection System.

Endpoints:
  GET    /api/health         -> is the server / model ready?
  POST   /api/scan           -> analyze a URL and save the result
  GET    /api/dashboard      -> statistics computed from saved scans
  GET    /api/history        -> list previous scans
  GET    /api/history/<id>   -> full details of one previous scan
  DELETE /api/history        -> clear all history

SAFETY: submitted URLs are only analysed as text, never visited.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS

import prediction
from feature_extraction import normalize_url

ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = ROOT / "frontend"
DB_PATH = Path(os.environ.get("DB_PATH", Path(__file__).resolve().parent / "scans.db"))
# The frontend folder is served by Flask too, so the whole app runs from one URL.
app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024      # reject huge requests
# CORS only matters if you open the HTML with VS Code "Live Server" (another port)
CORS(app, resources={r"/api/*": {"origins": [r"http://127.0.0.1:\d+", r"http://localhost:\d+"]}})


# ----------------------------------------------------------------------------
# Database helpers (SQLite)
# ----------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            label TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            model_probability REAL NOT NULL,
            created_at TEXT NOT NULL,      -- UTC, ISO format
            details TEXT NOT NULL          -- full result as JSON
        )""")
    conn.commit()
    conn.close()


def get_db():
    """One database connection per request."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def row_to_summary(row):
    return {
        "id": row["id"],
        "url": row["url"],
        "label": row["label"],
        "risk_score": row["risk_score"],
        "model_probability": row["model_probability"],
        "created_at": row["created_at"],     # UTC; the browser converts to local time
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/api/health")
def health():
    try:
        prediction.load_model()
        return jsonify({"status": "ok", "model_loaded": True})
    except prediction.ModelNotAvailableError as err:
        return jsonify({"status": "degraded", "model_loaded": False, "error": str(err)}), 503


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "url" not in data:
        return jsonify({"error": "Send JSON like {\"url\": \"https://example.com\"}."}), 400

    # 1. Validate (text checks only)
    try:
        clean_url, scheme_assumed = normalize_url(data["url"])
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    # 2. Predict
    try:
        result = prediction.analyze(clean_url)
    except prediction.ModelNotAvailableError as err:
        return jsonify({"error": str(err)}), 503
    except Exception:
        app.logger.exception("Prediction failed")
        return jsonify({"error": "Something went wrong while analysing the URL."}), 500

    result["scheme_assumed"] = scheme_assumed
    result["created_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # 3. Save to history
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans (url, label, risk_score, model_probability, created_at, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (clean_url, result["label"], result["risk_score"],
         result["model_probability"], result["created_at"], json.dumps(result)))
    db.commit()
    result["id"] = cur.lastrowid
    return jsonify(result), 200


@app.get("/api/dashboard")
def dashboard():
    db = get_db()
    counts = {"Phishing": 0, "Suspicious": 0, "Low Risk": 0}
    for row in db.execute("SELECT label, COUNT(*) AS n FROM scans GROUP BY label"):
        counts[row["label"]] = row["n"]
    total = sum(counts.values())

    avg = db.execute("SELECT AVG(risk_score) AS a FROM scans").fetchone()["a"]

    # Scans per day for the last 7 days (UTC days), with zeros filled in
    today = datetime.now(timezone.utc).date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
    per_day = {d: {"date": d, "phishing": 0, "suspicious": 0, "low_risk": 0} for d in days}
    key = {"Phishing": "phishing", "Suspicious": "suspicious", "Low Risk": "low_risk"}
    rows = db.execute(
        "SELECT substr(created_at, 1, 10) AS day, label, COUNT(*) AS n FROM scans "
        "WHERE substr(created_at, 1, 10) >= ? GROUP BY day, label", (days[0],))
    for row in rows:
        if row["day"] in per_day:
            per_day[row["day"]][key[row["label"]]] = row["n"]

    recent = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()

    return jsonify({
        "total_scans": total,
        "phishing": counts["Phishing"],
        "suspicious": counts["Suspicious"],
        "low_risk": counts["Low Risk"],
        "average_risk_score": round(avg, 1) if avg is not None else None,
        "per_day": list(per_day.values()),
        "recent": [row_to_summary(r) for r in recent],
    })


@app.get("/api/history")
def history():
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except ValueError:
        return jsonify({"error": "limit must be a number."}), 400
    rows = get_db().execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return jsonify({"count": len(rows), "scans": [row_to_summary(r) for r in rows]})


@app.get("/api/history/<int:scan_id>")
def history_item(scan_id):
    row = get_db().execute("SELECT details FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Scan not found."}), 404
    result = json.loads(row["details"])
    result["id"] = scan_id
    return jsonify(result)


@app.delete("/api/history")
def clear_history():
    db = get_db()
    deleted = db.execute("DELETE FROM scans").rowcount
    db.commit()
    return jsonify({"deleted": deleted})


# ----------------------------------------------------------------------------
# Error handlers: always JSON for /api, never leak server details
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return "Page not found", 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify({"error": "Method not allowed for this endpoint."}), 405


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "Request is too large."}), 413


@app.errorhandler(500)
def server_error(_e):
    return jsonify({"error": "Internal server error."}), 500


# ----------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    # Port 5001, not 5000: on macOS, port 5000 is used by AirPlay Receiver.
    # Debug mode is OFF by default because it can expose server internals.
    app.run(host="127.0.0.1", port=5001, debug=os.environ.get("FLASK_DEBUG") == "1")