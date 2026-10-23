"""B5 trust bridge roundtrip tests.

Verifies through a real Flask test client (full request stack):
  1. sign_request_headers -> verify_signed_request (happy path, with body)
  2. replay window enforcement (stale timestamps rejected)
  3. unknown key-id / missing headers / tampered body rejected with stable
     machine-readable kinds
  4. zero-downtime rotation: two key-ids live side by side
  5. response signing canonical format (what the B1 worker verifies)
  6. CROSS-LANGUAGE: a Node signature (same canonical format as trust.ts)
     verifies in Python

Run:  pytest test_trust.py -v
(Needs `cryptography` and `flask`; the Node part skips gracefully.)
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import trust

HERE = Path(__file__).parent


# ---------------------------------------------------------------------------
# Flask test app: exactly how sync_service.py protects POST /api/sync/run
# ---------------------------------------------------------------------------


def make_app(public_keys: dict) -> "object":
    from flask import Flask, jsonify, request

    app = Flask(__name__)

    @app.post("/api/sync/run")
    def run():
        try:
            key_id = trust.verify_signed_request(request, public_keys)
            return jsonify({"status": "ok", "key": key_id}), 200
        except trust.TrustError as exc:
            return jsonify({"status": "error", "error": exc.kind, "detail": str(exc)}), 401

    return app


def post(client, headers: dict, body: bytes = b""):
    return client.post("/api/sync/run", data=body, headers=headers)


@pytest.fixture()
def env():
    private_key = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    public_keys = trust.load_public_keys('{"sync-main": "%s"}' % pub_b64)
    app = make_app(public_keys)
    return private_key, public_keys, app.test_client()


def sign(key, key_id="sync-main", body=b"", timestamp=None):
    return trust.sign_request_headers(key, key_id, "POST", "/api/sync/run", body, timestamp=timestamp)


# ---------------------------------------------------------------------------


def test_roundtrip_ok(env):
    private_key, _keys, client = env
    res = post(client, sign(private_key))
    assert res.status_code == 200
    assert res.get_json() == {"status": "ok", "key": "sync-main"}


def test_roundtrip_with_body(env):
    private_key, _keys, client = env
    body = b'{"force": true, "answer": 42}'
    res = post(client, sign(private_key, body=body), body)
    assert res.status_code == 200


def test_tampered_body_rejected(env):
    private_key, _keys, client = env
    headers = sign(private_key, body=b"original")
    res = post(client, headers, body=b"tampered!")
    assert res.status_code == 401
    assert res.get_json()["error"] == "bad_signature"


def test_stale_timestamp_rejected(env):
    private_key, _keys, client = env
    old_ts = str(int(time.time()) - 3600)
    res = post(client, sign(private_key, timestamp=old_ts))
    assert res.status_code == 401
    assert res.get_json()["error"] == "stale_timestamp"


def test_missing_headers_rejected(env):
    _priv, _keys, client = env
    res = post(client, {})
    assert res.status_code == 401
    assert res.get_json()["error"] == "missing_headers"


def test_unknown_key_rejected(env):
    private_key, _keys, client = env
    res = post(client, sign(private_key, key_id="attacker-key"))
    assert res.status_code == 401
    assert res.get_json()["error"] == "unknown_key"


def test_garbage_signature_rejected(env):
    private_key, _keys, client = env
    headers = sign(private_key)
    headers["X-Luma-Signature"] = base64.b64encode(b"\x00" * 64).decode()
    res = post(client, headers)
    assert res.status_code == 401
    assert res.get_json()["error"] == "bad_signature"


def test_rotation_two_keys_live():
    """Zero-downtime rotation: old and new key-ids verify simultaneously."""
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old_pub = base64.b64encode(old_private.public_key().public_bytes_raw()).decode()
    new_pub = base64.b64encode(new_private.public_key().public_bytes_raw()).decode()
    public_keys = trust.load_public_keys('{"sync-main": "%s", "sync-2026-11": "%s"}' % (old_pub, new_pub))
    client = make_app(public_keys).test_client()
    for key_id, key in (("sync-main", old_private), ("sync-2026-11", new_private)):
        res = post(client, sign(key, key_id=key_id))
        assert res.status_code == 200
        assert res.get_json()["key"] == key_id


def test_response_signing_canonical():
    """The RESPONSE canonical format is exactly what the B1 worker verifies."""
    private_key = Ed25519PrivateKey.generate()
    body = b'{"top_brands": [], "evidence": {}}'
    headers = trust.sign_response_body(body, private_key, timestamp="1771000000")
    assert set(headers) == {"X-Luma-Timestamp", "X-Luma-Signature"}
    message = trust.response_canonical_message("1771000000", body)
    private_key.public_key().verify(base64.b64decode(headers["X-Luma-Signature"]), message)


# ---------------------------------------------------------------------------
# Cross-language: Node signs (same canonical message as trust.ts) -> Python
# ---------------------------------------------------------------------------

NODE_INLINE = """
const { createHash, createPrivateKey, sign } = require('node:crypto');
const seed = Buffer.from(process.argv[1], 'base64');
const DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const key = createPrivateKey({ key: Buffer.concat([DER_PREFIX, seed]), format: 'der', type: 'pkcs8' });
const timestamp = process.argv[2];
const message = Buffer.concat([
  Buffer.from(timestamp + '|POST|/api/sync/run|', 'ascii'),
  createHash('sha256').update(new Uint8Array(0)).digest(),
]);
const signature = sign(null, message, key).toString('base64');
console.log(JSON.stringify({ timestamp, signature }));
"""


def test_node_signature_verifies_in_python(env):
    import shutil

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    private_key, _keys, client = env
    seed_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()
    timestamp = str(int(time.time()))
    proc = subprocess.run(
        [node, "-e", NODE_INLINE, "--", seed_b64, timestamp],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[:300]
    out = json.loads(proc.stdout.strip())
    res = post(client, {
        "X-Luma-Timestamp": out["timestamp"],
        "X-Luma-Key-Id": "sync-main",
        "X-Luma-Signature": out["signature"],
    })
    assert res.status_code == 200
    assert res.get_json()["key"] == "sync-main"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
