"""Ember Signal — Flask surface over the SQLite signal data and the ember-lite engine.

Serves three things:
  GET /                  the dashboard (index.html at the repo root)
  GET /api/signals       top brands from data.db + the evidence JSON
  GET /api/health        liveness probe (Render healthCheckPath)

and, when an ember-lite checkout is configured, the read-only engine routes
registered by `ember_signal.build_blueprint()`.
"""

import json
import os
import sqlite3

from flask import Flask, jsonify, send_from_directory

from ember_signal import build_blueprint, engine_status
from ember_signal.trust import after_request_response_signing
from sync_service import build_sync_blueprint

# index.html lives at the repo root (not templates/ or static/), matching the
# other Ember repos, so it is served directly rather than via render_template.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Engine-backed routes: /api/evidence/chain, /api/perceive, /api/gate,
# /api/govern, /api/verify, /api/engine. Each returns 503 when the engine is
# absent rather than fabricating data.
app.register_blueprint(build_blueprint())

# B4: Runtime data sync endpoints (/api/sync/run, /api/sync/status)
app.register_blueprint(build_sync_blueprint())

DB_PATH = os.path.join(BASE_DIR, "data.db")
EVIDENCE_PATH = os.path.join(BASE_DIR, "ember-signal-evidence.json")

# Only these columns are ever returned, so the query cannot be widened by input.
TOP_BRANDS_QUERY = (
    "SELECT name, country, brand_value FROM brands "
    "WHERE brand_value IS NOT NULL ORDER BY brand_value DESC LIMIT 10;"
)


def get_db_data():
    # Context manager guarantees the connection is closed even if the query raises.
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(TOP_BRANDS_QUERY).fetchall()


def get_json_evidence():
    # A missing or malformed evidence file must degrade gracefully, not 500.
    try:
        with open(EVIDENCE_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": "evidence_file_missing", "path": EVIDENCE_PATH}
    except (json.JSONDecodeError, OSError) as exc:
        return {"error": "evidence_file_invalid_json", "detail": str(exc)}


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/health")
def health():
    # The service is "healthy" whenever it is serving; the engine field reports
    # the optional engine separately rather than hiding it. Render probes this.
    return jsonify({
        "status": "healthy",
        "service": "ember-signal",
        "engine": engine_status(),
    })


@app.after_request
def add_cors_headers(response):
    # Off by default. Set EMBER_CORS_ORIGIN (e.g. https://lumafoundry.live) to
    # let a browser origin read these endpoints.
    origin = os.environ.get("EMBER_CORS_ORIGIN")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


@app.route("/api/signals")
def get_signals():
    return jsonify({
        "top_brands": get_db_data(),
        "evidence": get_json_evidence(),
    })


# B5: Attach response signing to /api/signals so the B1 edge worker can verify payload integrity.
# If LUMA_RESPONSE_SIGNING_KEY is not set in the environment, this safely does nothing.
after_request_response_signing(app, path="/api/signals")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port) 
