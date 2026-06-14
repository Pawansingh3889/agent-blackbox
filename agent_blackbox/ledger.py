"""Append-only, tamper-evident ledger for AI agent actions.

Every action an agent takes (a SQL query, a tool call, a file read) is recorded
as one row. Each row carries the hash of the row before it, so the whole log is
a chain: change or drop any row after the fact and the chain no longer adds up.
`verify()` walks the chain and tells you the first row that doesn't.

Storage is a single SQLite file. No services, no network, nothing leaves the
machine. If AGENT_BLACKBOX_KEY is set (or a key is passed in), rows are chained
with HMAC-SHA256 instead of plain SHA-256, so someone who can write to the file
still can't forge a valid chain without the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

GENESIS = "0" * 64


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _canonical(obj: dict) -> bytes:
    # Deterministic bytes for hashing: sorted keys, no incidental whitespace.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _as_text(value: Any) -> Optional[str]:
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(data: bytes, key: Optional[bytes]) -> str:
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: str
    actor: str
    action: str
    target: Optional[str]
    payload: Optional[str]
    meta: Optional[str]
    prev_hash: str
    hash: str
    outcome: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "payload": self.payload,
            "meta": self.meta,
            "outcome": self.outcome,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    verified: int
    broken_seq: Optional[int] = None
    detail: str = "ok"

    def __bool__(self) -> bool:
        return self.ok


# Columns that feed the hash, in a fixed order. `hash` is derived, not hashed.
_CORE = ("seq", "ts", "actor", "action", "target", "payload", "meta", "prev_hash")


class Ledger:
    def __init__(self, path: str = "agent_blackbox.db", key: Optional[Any] = None) -> None:
        self.path = str(path)
        if key is None:
            env = os.environ.get("AGENT_BLACKBOX_KEY")
            key = env if env else None
        if isinstance(key, str):
            key = key.encode("utf-8")
        self._key: Optional[bytes] = key
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                seq       INTEGER PRIMARY KEY,
                ts        TEXT NOT NULL,
                actor     TEXT NOT NULL,
                action    TEXT NOT NULL,
                target    TEXT,
                payload   TEXT,
                meta      TEXT,
                outcome   TEXT,
                prev_hash TEXT NOT NULL,
                hash      TEXT NOT NULL
            )
            """
        )
        # Older ledgers predate the outcome column; add it so they keep working.
        have = {r["name"] for r in self._conn.execute("PRAGMA table_info(entries)")}
        if "outcome" not in have:
            self._conn.execute("ALTER TABLE entries ADD COLUMN outcome TEXT")
        self._conn.commit()

    def _hash_row(self, row: dict) -> str:
        core = {k: row[k] for k in _CORE}
        # Outcome joins the hash only when present, so ledgers written before
        # this column existed still verify unchanged.
        if row.get("outcome") is not None:
            core["outcome"] = row["outcome"]
        return _digest(_canonical(core), self._key)

    def _last(self) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT seq, hash FROM entries ORDER BY seq DESC LIMIT 1")
        return cur.fetchone()

    def record(
        self,
        actor: str,
        action: str,
        target: Optional[str] = None,
        payload: Any = None,
        meta: Any = None,
        outcome: Any = None,
    ) -> Entry:
        """Append one action to the ledger and return the new Entry.

        actor   - who acted, e.g. "floormind" or "model:gemma3:12b"
        action  - what they did, e.g. "sql_query", "tool_call", "file_read"
        target  - what it touched, e.g. "warehouse.orders" or a server name
        payload - the actual content (SQL text, args). str or any JSON value.
        meta    - extra context (row count, status, duration_ms, user).
        outcome - how it went, e.g. "correct", "incorrect", "error", or a score.
                  Recorded so you can trend quality over time, not just activity.
        """
        last = self._last()
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["hash"] if last else GENESIS
        row = {
            "seq": seq,
            "ts": _utcnow(),
            "actor": actor,
            "action": action,
            "target": target,
            "payload": _as_text(payload),
            "meta": _as_text(meta),
            "outcome": _as_text(outcome),
            "prev_hash": prev_hash,
        }
        row_hash = self._hash_row(row)
        self._conn.execute(
            "INSERT INTO entries (seq, ts, actor, action, target, payload, meta, outcome, prev_hash, hash)"
            " VALUES (:seq, :ts, :actor, :action, :target, :payload, :meta, :outcome, :prev_hash, :hash)",
            {**row, "hash": row_hash},
        )
        self._conn.commit()
        return Entry(hash=row_hash, **row)

    def verify(self) -> VerifyResult:
        """Walk the chain. Returns ok=True only if every link is intact."""
        prev = GENESIS
        verified = 0
        cur = self._conn.execute(
            "SELECT seq, ts, actor, action, target, payload, meta, outcome, prev_hash, hash FROM entries ORDER BY seq"
        )
        for r in cur:
            if r["prev_hash"] != prev:
                return VerifyResult(False, verified, r["seq"], "broken link: prev_hash does not match the row before it")
            expect = self._hash_row({k: r[k] for k in (*_CORE, "outcome")})
            if expect != r["hash"]:
                return VerifyResult(False, verified, r["seq"], "row altered: stored hash does not match its contents")
            prev = r["hash"]
            verified += 1
        return VerifyResult(True, verified, None, "ok")

    def entries(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Iterator[Entry]:
        clauses, params = [], {}
        if actor is not None:
            clauses.append("actor = :actor")
            params["actor"] = actor
        if action is not None:
            clauses.append("action = :action")
            params["action"] = action
        if since is not None:
            clauses.append("ts >= :since")
            params["since"] = since
        if until is not None:
            clauses.append("ts <= :until")
            params["until"] = until
        sql = "SELECT * FROM entries"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        for r in self._conn.execute(sql, params):
            yield Entry(**{k: r[k] for k in r.keys()})

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) AS n FROM entries").fetchone()["n"]

    def outcome_summary(self, since: Optional[str] = None, until: Optional[str] = None) -> dict:
        """Count entries by recorded outcome (entries with no outcome are skipped).

        Pass since/until (ISO timestamps) to look at a window, e.g. the last
        seven days, which is how you watch quality drift instead of waiting for
        complaints.
        """
        counts: dict = {}
        for e in self.entries(since=since, until=until):
            if e.outcome is not None:
                counts[e.outcome] = counts.get(e.outcome, 0) + 1
        return dict(sorted(counts.items()))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
