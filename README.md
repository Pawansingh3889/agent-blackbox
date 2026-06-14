# agent-blackbox

[![CI](https://github.com/Pawansingh3889/agent-blackbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Pawansingh3889/agent-blackbox/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

An append-only, tamper-evident log of everything an AI agent does to your data. Runs on your own machine, stores to a single SQLite file, no dependencies, nothing leaves the network.

Most AI guardrail tools decide whether an action is allowed and then forget about it. The question that comes up later, in an incident review or an audit, is different: *what did the agent actually do, and can you prove the record wasn't edited afterwards?* That's what this is for.

## How it works

Every action is one row. Each row stores the hash of the row before it, so the log is a chain. Change a row, delete a row, or reorder rows after the fact and the chain stops adding up. `verify()` walks it and points at the first row that doesn't check out.

Set `AGENT_BLACKBOX_KEY` and rows are chained with HMAC-SHA256 instead of plain SHA-256. Then someone who can write to the file still can't forge a valid chain without the key.

## Install

```bash
pip install agent-blackbox      # once published
# or, from a clone:
pip install -e .
```

## Use it in code

```python
from agent_blackbox import Ledger

led = Ledger("agent_blackbox.db")

led.record(
    actor="floormind",
    action="sql_query",
    target="warehouse.orders",
    payload="SELECT TOP 100 * FROM orders WHERE region = 'NE'",
    meta={"rows": 100, "status": "ok", "duration_ms": 42},
    outcome="correct",   # how it went: "correct" / "incorrect" / "error" or a score
)

result = led.verify()
print(result.ok, result.verified)   # True 1
```

`record()` takes:

- `actor` — who acted, e.g. `"floormind"` or `"model:gemma3:12b"`
- `action` — what they did, e.g. `"sql_query"`, `"tool_call"`, `"file_read"`
- `target` — what it touched, e.g. a table or server name
- `payload` — the actual content (SQL text, tool args); a string or any JSON value
- `meta` — extra context (row count, status, duration, user)
- `outcome` — how it went (`"correct"`, `"incorrect"`, `"error"`, or a score). Optional, tamper-evident like the rest, and surfaced by `stats` so you can trend quality over time, not just activity

## Command line

```bash
agent-blackbox verify             # check the chain is intact
agent-blackbox verify --json      # machine-readable verification result
agent-blackbox tail -n 20         # recent actions
agent-blackbox stats              # counts by action, actor and outcome
agent-blackbox stats --json       # machine-readable summary counts
agent-blackbox export --format csv > audit.csv
```

`verify` exits non-zero if the chain is broken, so it drops into CI or a cron check.

## Wiring it into an agent

It's one line wherever the agent touches data. For a read-only SQL MCP server, record inside the query path:

```python
# in run_query(), after the query runs
led.record("sql-explorer-mcp", "sql_query", target=server, payload=sql,
           meta={"rows": len(rows), "status": "ok"})
```

The same call fits any tool handler. The point is that the log is written by the
thing executing the action, not trusted to the model.

## What it is not

It records and proves; it does not block. Pair it with a guardrail (read-only DB
users, a SQL linter, an allow-list) for prevention. This is the part that lets you
answer "what happened" afterwards, with a record you can stand behind.

## License

MIT.
