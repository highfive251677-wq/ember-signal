"""Integration test: B5-signed request -> B4 sync endpoint -> atomic swap.

This exercises the FULL premium path exactly as GitHub Actions will hit it:

    GitHub Actions (signed POST) -> Flask /api/sync/run
        -> verify_signed_request (Ed25519, B5)
        -> clone (stubbed to a local fixture db)
        -> sync_core.sync (deterministic transform + atomic swap)
        -> GET /api/sync/status (public observability)

Run:  pytest test_sync_service.py -v
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# trust.py lives in ../b5-trust-bridge in this package (deployed: ember_signal/trust.py)
sys.path.insert(0, str(Path(__file__).parent.parent / "b5-trust-bridge"))

import sync_core  # noqa: E402
import sync_service  # noqa: E402
import trust  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))


# --- fixture: a backend db (same helper as test_sync.py) ----------------------


def make_backend_db(path: str) -> None:
    import sqlite3

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE institutions (id INTEGER PRIMARY KEY, name TEXT, city TEXT);
        CREATE TABLE evidence_items (
            id INTEGER PRIMARY KEY, title TEXT, source_url TEXT, observed_at TEXT,
            review_status TEXT, excerpt TEXT, institution_id INTEGER, platform TEXT);
        """
    )
    conn.executemany(
        "INSERT INTO institutions (id, name, city) VALUES (?,?,?)",
        [(1, "STI Myanmar College", "Yangon"), (2, "BUC", "Yangon")],
    )
    conn.executemany(
        "INSERT INTO evidence_items (id, title, source_url, observed_at, review_status, excerpt, institution_id, platform) VALUES (?,?,?,?,?,?,?,?)",
        [
            (1, "Programme page", "http://a", "2026-02-01T00:00:00Z", "approved", "excerpt A", 1, "web"),
            (2, "Needs review", "http://b", "2026-04-01T00:00:00Z", "source_review_required", "excerpt B", 2, "web"),
            (3, "Fresh signal", "http://c", "2026-05-01T00:00:00Z", "unreviewed", None, 2, "telegram"),
            (4, "Bad evidence", "http://x", "2026-01-01T00:00:00Z", "rejected", "junk", 1, "web"),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def app_env(tmp_path: Path, monkeypatch):
    """Flask app with the sync blueprint, a stubbed clone, and real keys."""
    backend_db = tmp_path / "backend" / "ember_signal.db"
    backend_db.parent.mkdir()
    make_backend_db(str(backend_db))
    target_dir = tmp_path / "webroot"
    target_dir.mkdir()

    from flask import Flask

    app = Flask(__name__, root_path=str(target_dir))
    app.config["TESTING"] = True
    app.register_blueprint(sync_service.build_sync_blueprint())

    private_key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    app.config["LUMA_TRUST_PUBLIC_KEYS"] = json.dumps({"sync-main": pub_b64})

    # Stub the git clone: "cloning" = pointing at the fixture db.
    monkeypatch.setattr(sync_service, "_clone_source", lambda dest: str(backend_db))
    # Purge is best-effort and unconfigured in this environment.
    monkeypatch.setattr(sync_service, "_purge_edge_cache", lambda: {"attempted": False, "reason": "not_configured"})

    return app, private_key, target_dir


def signed_headers(private_key: Ed25519PrivateKey) -> dict:
    return trust.sign_request_headers(private_key, "sync-main", "POST", "/api/sync/run", b"")


# ---------------------------------------------------------------------------


def test_signed_sync_run_end_to_end(app_env):
    app, private_key, target_dir = app_env
    client = app.test_client()

    res = client.post(
        "/api/sync/run",
        data=b"",
        headers=signed_headers(private_key),
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "ok"
    sync = body["sync"]
    assert sync["ok"] is True
    assert sync["changed"] is True
    assert sync["records"] == 3  # 4 items - 1 rejected
    assert sync["verified"] == 1
    assert sync["pending"] == 1
    assert sync["observed"] == 1

    # outputs really landed in the (fake) webroot
    assert (target_dir / "data.db").exists()
    evidence = json.loads((target_dir / "ember-signal-evidence.json").read_text(encoding="utf-8"))
    assert len(evidence["records"]) == 3
    assert all(r["status"] != "rejected" for r in evidence["records"])


def test_unsigned_request_is_refused(app_env):
    app, _priv, _target = app_env
    client = app.test_client()
    res = client.post("/api/sync/run", data=b"")
    assert res.status_code == 401
    assert res.get_json()["error"] == "missing_headers"


def test_tampered_request_is_refused(app_env):
    app, private_key, _target = app_env
    client = app.test_client()
    headers = signed_headers(private_key)
    headers["X-Luma-Timestamp"] = str(int(headers["X-Luma-Timestamp"]) - 99999)  # stale
    res = client.post("/api/sync/run", data=b"", headers=headers)
    assert res.status_code == 401
    assert res.get_json()["error"] == "stale_timestamp"


def test_status_endpoint_reports_last_sync(app_env):
    app, private_key, _target = app_env
    client = app.test_client()

    # before any sync
    res = client.get("/api/sync/status")
    assert res.status_code == 200
    assert res.get_json()["status"] == "never_synced"

    client.post("/api/sync/run", data=b"", headers=signed_headers(private_key))
    res = client.get("/api/sync/status")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "ok"
    assert body["sync"]["records"] == 3


def test_idempotent_double_sync(app_env):
    app, private_key, _target = app_env
    client = app.test_client()
    client.post("/api/sync/run", data=b"", headers=signed_headers(private_key))
    res = client.post("/api/sync/run", data=b"", headers=signed_headers(private_key))
    body = res.get_json()
    assert body["sync"]["changed"] is False  # same source, honest no-op


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
