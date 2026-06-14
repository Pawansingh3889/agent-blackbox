import json

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
