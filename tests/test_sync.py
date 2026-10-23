"""B4 sync tests — deterministic transform, change detection, atomic swap, lock.

Run with pytest (or plain `python test_sync.py`).

The fixtures recreate the ember-signal-backend schema (institutions,
evidence_items) exactly as the real ember_signal.db uses them, including all
four review statuses, so the transform behaviour is tested against reality.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

import sync_core


def make_backend_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE institutions (
            id INTEGER PRIMARY KEY,
            name TEXT,
            city TEXT
        );
        CREATE TABLE evidence_items (
            id INTEGER PRIMARY KEY,
            title TEXT,
            source_url TEXT,
            observed_at TEXT,
            review_status TEXT,
            excerpt TEXT,
            institution_id INTEGER,
            platform TEXT
        );
        """
    )
    conn.executemany(
        "INSERT INTO institutions (id, name, city) VALUES (?,?,?)",
        [
            (1, "STI Myanmar College", "Yangon"),
            (2, "Business University College", "Yangon"),
            (3, "AUSTON", "Mandalay"),
            (4, "Rejected Institute", "Naypyidaw"),
        ],
    )
    conn.executemany(
        "INSERT INTO evidence_items (id, title, source_url, observed_at, review_status, excerpt, institution_id, platform) VALUES (?,?,?,?,?,?,?,?)",
        [
            # rejected -> must be EXCLUDED
            (1, "Bad evidence", "http://x", "2026-01-01T00:00:00Z", "rejected", "junk", 4, "web"),
            # approved -> verified
            (2, "Programme page", "http://a", "2026-02-01T00:00:00Z", "approved", "excerpt A", 1, "web"),
            (3, None, None, "2026-03-01T00:00:00Z", "approved", None, 1, "facebook"),
            # source_review_required -> pending
            (4, "Needs review", "http://b", "2026-04-01T00:00:00Z", "source_review_required", "excerpt B", 2, "web"),
            # unreviewed -> observed
            (5, "Fresh signal", "http://c", "2026-05-01T00:00:00Z", "unreviewed", None, 3, "telegram"),
            # deliberately unsorted insert order (id 6 before 2)
            (6, "Older approved", "http://d", "2026-01-15T00:00:00Z", "approved", "excerpt D", 2, "web"),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def source_db(tmp_path: Path) -> str:
    path = str(tmp_path / "ember_signal.db")
    make_backend_db(path)
    return path


@pytest.fixture()
def target(tmp_path: Path) -> str:
    d = tmp_path / "target"
    d.mkdir()
    return str(d)


def read_evidence(target: str) -> dict:
    return json.loads((Path(target) / "ember-signal-evidence.json").read_text(encoding="utf-8"))


def read_brands(target: str) -> list[tuple]:
    conn = sqlite3.connect(str(Path(target) / "data.db"))
    try:
        return conn.execute("SELECT id, name, country, brand_value FROM brands ORDER BY id").fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------


def test_sync_produces_both_outputs(source_db: str, target: str):
    report = sync_core.sync(source_db, target)
    assert report["ok"] is True
    assert report["changed"] is True
    assert (Path(target) / "data.db").exists()
    assert (Path(target) / "ember-signal-evidence.json").exists()
    assert (Path(target) / sync_core.STATE_FILE).exists()


def test_status_mapping_and_rejected_exclusion(source_db: str, target: str):
    sync_core.sync(source_db, target)
    evidence = read_evidence(target)
    statuses = {r["status"] for r in evidence["records"]}
    assert statuses == {"verified", "pending", "observed"}  # no rejected, no raw names
    assert all(r["reference"].startswith("ember-signal-backend:evidence:") for r in evidence["records"])
    assert len(evidence["records"]) == 5  # 6 items - 1 rejected


def test_deterministic_ordering(source_db: str, target: str):
    sync_core.sync(source_db, target)
    records = read_evidence(target)["records"]
    group = {"verified": 0, "pending": 1, "observed": 2}
    keys = [(group[r["status"]], r["observedAt"], int(r["id"])) for r in records]
    assert keys == sorted(keys)


def test_byte_exact_determinism(source_db: str, target: str):
    sync_core.sync(source_db, target)
    first = (Path(target) / "ember-signal-evidence.json").read_bytes()
    # reset state so changed=True again (fresh updatedAt) — records must still
    # be identical; only the updatedAt line may differ.
    (Path(target) / sync_core.STATE_FILE).unlink()
    sync_core.sync(source_db, target)
    second = (Path(target) / "ember-signal-evidence.json").read_bytes()
    recs1 = json.loads(first)["records"]
    recs2 = json.loads(second)["records"]
    assert recs1 == recs2
    assert json.dumps(recs1, sort_keys=True, ensure_ascii=False) == json.dumps(recs2, sort_keys=True, ensure_ascii=False)


def test_change_detection_noop_resync(source_db: str, target: str):
    sync_core.sync(source_db, target)
    before_evidence = (Path(target) / "ember-signal-evidence.json").read_bytes()
    before_db = (Path(target) / "data.db").read_bytes()
    before_mtime = (Path(target) / "ember-signal-evidence.json").stat().st_mtime_ns

    report = sync_core.sync(source_db, target)  # same source -> no-op
    assert report["changed"] is False
    assert (Path(target) / "ember-signal-evidence.json").read_bytes() == before_evidence
    assert (Path(target) / "data.db").read_bytes() == before_db
    assert (Path(target) / "ember-signal-evidence.json").stat().st_mtime_ns == before_mtime


def test_real_change_triggers_rewrite(source_db: str, target: str):
    sync_core.sync(source_db, target)
    conn = sqlite3.connect(source_db)
    conn.execute(
        "INSERT INTO evidence_items (id, title, source_url, observed_at, review_status, excerpt, institution_id, platform) "
        "VALUES (7, 'New evidence', 'http://e', '2026-06-01T00:00:00Z', 'unreviewed', ?, 3, 'web')",
        (None,),
    )
    conn.commit()
    conn.close()
    report = sync_core.sync(source_db, target)
    assert report["changed"] is True
    assert report["records"] == 6
    assert read_evidence(target)["records"][-1]["title"] == "New evidence"


def test_top_institutions_brands(source_db: str, target: str):
    sync_core.sync(source_db, target)
    brands = read_brands(target)
    # Byte-exact with the deployed transform: the brands query JOINs over ALL
    # evidence rows, so an institution whose only evidence is rejected still
    # appears with its raw signal count (rejection only excludes RECORDS).
    assert len(brands) <= 10
    names = [b[1] for b in brands]
    # institutions 1 (2 approved) and 2 (2 items) lead;
    # tie broken by name ASC: "Business University College" < "STI Myanmar College"
    assert names[0] == "Business University College"
    assert "STI Myanmar College" in names
    counts = {b[1]: b[3] for b in brands}
    assert counts["STI Myanmar College"] == 2.0
    assert counts["Rejected Institute"] == 1.0  # raw count; its record is excluded


def test_lock_prevents_concurrent_sync(source_db: str, target: str):
    lock = Path(target) / sync_core.LOCK_FILE
    lock.write_text("12345")
    with pytest.raises(sync_core.SyncBusyError):
        sync_core.sync(source_db, target)


def test_stale_lock_is_broken(source_db: str, target: str):
    lock = Path(target) / sync_core.LOCK_FILE
    lock.write_text("12345")
    old = time.time() - sync_core.LOCK_STALE_SECONDS - 60
    os.utime(lock, (old, old))
    report = sync_core.sync(source_db, target)  # stale lock broken, sync proceeds
    assert report["ok"] is True
    assert not lock.exists()  # cleaned up


def test_missing_source_raises_sync_error(target: str):
    with pytest.raises(sync_core.SyncError):
        sync_core.sync("/nonexistent/ember_signal.db", target)


def test_atomicity_no_tmp_left_behind(source_db: str, target: str):
    sync_core.sync(source_db, target)
    leftovers = [p.name for p in Path(target).iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


import time  # noqa: E402  (used in test_stale_lock_is_broken)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
