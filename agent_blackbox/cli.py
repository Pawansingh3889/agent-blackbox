"""Command line interface for agent-blackbox.

    agent-blackbox verify   [--db PATH]
    agent-blackbox tail     [--db PATH] [-n N]
    agent-blackbox stats    [--db PATH]
    agent-blackbox export   [--db PATH] [--format jsonl|csv]
    agent-blackbox record   [--db PATH] --actor A --action B [--target T] [--payload P]

The key (for HMAC chaining) is read from AGENT_BLACKBOX_KEY when set.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys

from .ledger import Ledger


def _add_db(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db", default="agent_blackbox.db", help="path to the ledger file")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-blackbox", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify", help="check the chain is intact")
    p_verify.add_argument('--json', action='store_true', help='Emit machine-readable JSON output')
    _add_db(p_verify)

    p_tail = sub.add_parser("tail", help="show the most recent entries")
    _add_db(p_tail)
    p_tail.add_argument("-n", type=int, default=10, help="how many entries")

    p_stats = sub.add_parser("stats", help="summary counts")
    p_stats.add_argument('--json', action='store_true', help='Emit machine-readable JSON output')
    _add_db(p_stats) # or whatever helper it calls

    p_export = sub.add_parser("export", help="dump the whole ledger")
    _add_db(p_export)
    p_export.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")

    p_rec = sub.add_parser("record", help="append one entry (handy for shell hooks)")
    _add_db(p_rec)
    p_rec.add_argument("--actor", required=True)
    p_rec.add_argument("--action", required=True)
    p_rec.add_argument("--target", default=None)
    p_rec.add_argument("--payload", default=None)

    args = parser.parse_args(argv)
    led = Ledger(args.db)

    if args.cmd == "verify":
        res = led.verify()

        if args.json:
            verify_output = {
                "status": "OK" if res.ok else "FAIL",
                "verified_entries": res.verified
            }
            if not res.ok:
                verify_output["broken_seq"] = res.broken_seq
                verify_output["detail"] = res.detail
                
            print(json.dumps(verify_output))
            return 0 if res.ok else 1
            
        if res.ok:
            print(f"OK  {res.verified} entries, chain intact")
            return 0
        print(f"FAIL  broken at seq {res.broken_seq}: {res.detail} ({res.verified} verified before the break)")
        return 1

    if args.cmd == "tail":
        rows = list(led.entries())[-args.n :]
        for e in rows:
            print(f"[{e.seq}] {e.ts} {e.actor} {e.action} {e.target or ''}".rstrip())
        return 0

    if args.cmd == "stats":
            rows = list(led.entries())
            by_action: dict[str, int] = {}
            by_actor: dict[str, int] = {}
            for e in rows:
                by_action[e.action] = by_action.get(e.action, 0) + 1
                by_actor[e.actor] = by_actor.get(e.actor, 0) + 1
                
            if args.json:
                stats_output = {
                    "entries_count": len(rows),
                    "range": {
                        "start": rows[0].ts if rows else None,
                        "end": rows[-1].ts if rows else None
                    },
                    "by_action": dict(sorted(by_action.items())),
                    "by_actor": dict(sorted(by_actor.items()))
                }
                print(json.dumps(stats_output))
                return 0
                
            # Default human-readable text output
            print(f"entries: {len(rows)}")
            if rows:
                print(f"range:   {rows[0].ts}  ->  {rows[-1].ts}")
            print("by action: " + ", ".join(f"{k}={v}" for k, v in sorted(by_action.items())))
            print("by actor:  " + ", ".join(f"{k}={v}" for k, v in sorted(by_actor.items())))
            return 0

    if args.cmd == "export":
        rows = led.entries()
        if args.format == "jsonl":
            for e in rows:
                print(json.dumps(e.as_dict(), ensure_ascii=False))
        else:
            w = csv.writer(sys.stdout)
            w.writerow(["seq", "ts", "actor", "action", "target", "payload", "meta", "prev_hash", "hash"])
            for e in rows:
                d = e.as_dict()
                w.writerow([d[c] for c in ("seq", "ts", "actor", "action", "target", "payload", "meta", "prev_hash", "hash")])
        return 0

    if args.cmd == "record":
        e = led.record(args.actor, args.action, target=args.target, payload=args.payload)
        print(f"recorded seq {e.seq} ({e.hash[:12]}...)")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
