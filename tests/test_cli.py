import json
import time

from agent_blackbox import Ledger
from agent_blackbox.cli import main


def test_verify_json_outputs_machine_readable_result(tmp_path, capsys):
    db = tmp_path / "a.db"
    led = Ledger(db)
    led.record("agent", "tool_call")
    led.close()

    assert main(["verify", "--db", str(db), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)

    assert payload == {
        "ok": True,
        "verified": 1,
        "broken_seq": None,
        "detail": "ok",
    }


def test_stats_json_outputs_counts(tmp_path, capsys):
    db = tmp_path / "a.db"
    led = Ledger(db)
    led.record("alice", "tool_call")
    led.record("alice", "sql_query")
    led.record("bob", "tool_call")
    led.close()

    assert main(["stats", "--db", str(db), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)

    assert payload["entries"] == 3
    assert payload["range"]["start"] is not None
    assert payload["range"]["end"] is not None
    assert payload["by_action"] == {"sql_query": 1, "tool_call": 2}
    assert payload["by_actor"] == {"alice": 2, "bob": 1}


def test_tail_accepts_entry_filters(tmp_path, capsys):
    db = tmp_path / "a.db"
    led = Ledger(db)
    led.record("alice", "tool_call", target="first")
    led.record("bob", "tool_call", target="second")
    led.record("alice", "sql_query", target="third")
    led.record("alice", "tool_call", target="fourth")
    led.close()

    assert (
        main(["tail", "--db", str(db), "--actor", "alice", "--action", "tool_call", "-n", "10"])
        == 0
    )

    out = capsys.readouterr().out.splitlines()

    assert len(out) == 2
    assert "alice tool_call first" in out[0]
    assert "alice tool_call fourth" in out[1]


def test_export_accepts_time_filters(tmp_path, capsys):
    db = tmp_path / "a.db"
    led = Ledger(db)
    led.record("agent", "tool_call", target="before")
    time.sleep(0.001)
    wanted = led.record("agent", "tool_call", target="wanted")
    time.sleep(0.001)
    led.record("agent", "tool_call", target="after")
    led.close()

    assert (
        main(["export", "--db", str(db), "--since", wanted.ts, "--until", wanted.ts])
        == 0
    )

    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines()]

    assert [row["target"] for row in rows] == ["wanted"]
