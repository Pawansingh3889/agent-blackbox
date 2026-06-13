import sqlite3

import pytest

from agent_ledger import Ledger
from agent_ledger.ledger import GENESIS


def test_record_chains_entries(tmp_path):
    led = Ledger(tmp_path / "a.db")
    e1 = led.record("floormind", "sql_query", target="warehouse.orders", payload="SELECT 1")
    e2 = led.record("floormind", "sql_query", target="warehouse.orders", payload="SELECT 2")
    assert e1.seq == 1 and e2.seq == 2
    assert e1.prev_hash == GENESIS
    assert e2.prev_hash == e1.hash
    assert e1.hash != e2.hash


def test_verify_passes_on_clean_ledger(tmp_path):
    led = Ledger(tmp_path / "a.db")
    for i in range(20):
        led.record("agent", "tool_call", target="t", payload={"i": i})
    res = led.verify()
    assert res.ok
    assert res.verified == 20
    assert res.broken_seq is None


def test_verify_detects_altered_row(tmp_path):
    db = tmp_path / "a.db"
    led = Ledger(db)
    led.record("agent", "sql_query", payload="SELECT * FROM payroll")
    led.record("agent", "sql_query", payload="SELECT 1")
    led.close()

    # Someone edits the log to hide what the agent really ran.
    raw = sqlite3.connect(db)
    raw.execute("UPDATE entries SET payload = 'SELECT 1' WHERE seq = 1")
    raw.commit()
    raw.close()

    res = Ledger(db).verify()
    assert not res.ok
    assert res.broken_seq == 1
    assert "altered" in res.detail


def test_verify_detects_deleted_row(tmp_path):
    db = tmp_path / "a.db"
    led = Ledger(db)
    for i in range(5):
        led.record("agent", "tool_call", payload={"i": i})
    led.close()

    raw = sqlite3.connect(db)
    raw.execute("DELETE FROM entries WHERE seq = 3")
    raw.commit()
    raw.close()

    res = Ledger(db).verify()
    assert not res.ok
    # seq 4 still points at seq 3's hash, which is now gone -> break shows at 4.
    assert res.broken_seq == 4


def test_hmac_key_blocks_forgery(tmp_path):
    db = tmp_path / "a.db"
    led = Ledger(db, key="super-secret")
    led.record("agent", "sql_query", payload="SELECT 1")
    led.close()

    # Tamperer rewrites a row and recomputes a *plain* sha256 hash, not knowing the key.
    import hashlib
    raw = sqlite3.connect(db)
    raw.row_factory = sqlite3.Row
    r = raw.execute("SELECT * FROM entries WHERE seq = 1").fetchone()
    forged_core = '{"seq":1,"ts":"%s","actor":"agent","action":"sql_query","target":null,"payload":"SELECT 999","meta":null,"prev_hash":"%s"}' % (r["ts"], r["prev_hash"])
    forged = hashlib.sha256(forged_core.encode()).hexdigest()
    raw.execute("UPDATE entries SET payload='SELECT 999', hash=? WHERE seq=1", (forged,))
    raw.commit()
    raw.close()

    # Verifier holds the key, so the forged hash doesn't check out.
    assert not Ledger(db, key="super-secret").verify().ok


def test_entries_filter(tmp_path):
    led = Ledger(tmp_path / "a.db")
    led.record("alice", "sql_query", payload="x")
    led.record("bob", "tool_call", payload="y")
    led.record("alice", "file_read", payload="z")
    assert [e.seq for e in led.entries(actor="alice")] == [1, 3]
    assert [e.seq for e in led.entries(action="tool_call")] == [2]
    assert led.count() == 3


def test_payload_dict_is_stored_deterministically(tmp_path):
    led = Ledger(tmp_path / "a.db")
    e = led.record("agent", "tool_call", payload={"b": 2, "a": 1})
    # keys sorted regardless of insertion order
    assert e.payload == '{"a":1,"b":2}'
    assert led.verify().ok


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
