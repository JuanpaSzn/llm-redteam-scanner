"""Persist every run and turn to SQLite so scans can be compared over time."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .pair import AttackResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY, started_at TEXT, mode TEXT, target TEXT, config TEXT
);
CREATE TABLE IF NOT EXISTS attacks (
  attack_id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, seed_id TEXT, technique TEXT,
  target TEXT, converters TEXT, success INTEGER, best_score INTEGER, secret TEXT, n_turns INTEGER
);
CREATE TABLE IF NOT EXISTS turns (
  attack_id INTEGER, iteration INTEGER, attacker_prompt TEXT, sent_prompt TEXT, response TEXT,
  score INTEGER, reasoning TEXT, leaked_secret TEXT, verified INTEGER, improvement TEXT
);
"""


class Store:
    def __init__(self, path: str | Path = "results/redscan.sqlite") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript(SCHEMA)

    def new_scan(self, mode: str, target: str, config: dict) -> str:
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
        self.db.execute("INSERT INTO scans VALUES (?,?,?,?,?)",
                        (scan_id, datetime.now(timezone.utc).isoformat(), mode, target, json.dumps(config)))
        self.db.commit()
        return scan_id

    def save(self, scan_id: str, r: AttackResult) -> None:
        cur = self.db.execute(
            "INSERT INTO attacks (scan_id, seed_id, technique, target, converters, success, best_score, "
            "secret, n_turns) VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, r.seed_id, r.technique, r.target, r.converters, int(r.success), r.best_score,
             r.secret, len(r.turns)),
        )
        self.db.executemany(
            "INSERT INTO turns VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(cur.lastrowid, t.iteration, t.attacker_prompt, t.sent_prompt, t.response, t.score, t.reasoning,
              t.leaked_secret, None if t.verified is None else int(t.verified), t.improvement)
             for t in r.turns],
        )
        self.db.commit()

    def latest_scan(self) -> str | None:
        row = self.db.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def attacks(self, scan_id: str | None = None) -> list[dict]:
        q = "SELECT scan_id, seed_id, technique, target, converters, success, best_score, secret, n_turns " \
            "FROM attacks" + (" WHERE scan_id = ?" if scan_id else "")
        cols = ["scan_id", "seed_id", "technique", "target", "converters", "success", "best_score", "secret",
                "n_turns"]
        return [dict(zip(cols, row, strict=True)) for row in self.db.execute(q, (scan_id,) if scan_id else ())]
