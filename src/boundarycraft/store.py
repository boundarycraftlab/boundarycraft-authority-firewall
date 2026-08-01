from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class StoredRequest:
    request_id: str
    origin_channel: str
    origin_sender: str
    request_text: str
    score: int
    summary: str
    reasons: tuple[str, ...]
    classifier_source: str
    status: str
    created_at: str
    decided_at: str | None
    approval_channel: str | None
    approval_sender: str | None
    receipt_hash: str | None


class AuthorityStore:
    def __init__(self, path: str | Path = "boundarycraft.db") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    origin_channel TEXT NOT NULL,
                    origin_sender TEXT NOT NULL,
                    request_text TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    classifier_source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    approval_channel TEXT,
                    approval_sender TEXT,
                    receipt_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_request(
        self,
        *,
        request_id: str,
        origin_channel: str,
        origin_sender: str,
        request_text: str,
        score: int,
        summary: str,
        reasons: tuple[str, ...],
        classifier_source: str,
        status: str,
    ) -> StoredRequest:
        created_at = _utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO requests (
                    request_id, origin_channel, origin_sender, request_text, score,
                    summary, reasons_json, classifier_source, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    origin_channel,
                    origin_sender,
                    request_text,
                    score,
                    summary,
                    json.dumps(reasons),
                    classifier_source,
                    status,
                    created_at,
                ),
            )
        return self.get_request(request_id)

    def get_request(self, request_id: str) -> StoredRequest:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise KeyError(request_id)
        return self._from_row(row)

    def decide(
        self,
        request_id: str,
        *,
        status: str,
        approval_channel: str,
        approval_sender: str,
    ) -> StoredRequest:
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if row is None:
                raise KeyError(request_id)
            if row["status"] != "pending":
                return self._from_row(row)

            previous = connection.execute(
                "SELECT receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["receipt_hash"] if previous else GENESIS_HASH
            decided_at = _utc_now()
            payload = {
                "request_id": request_id,
                "origin_channel": row["origin_channel"],
                "origin_sender": row["origin_sender"],
                "request_sha256": hashlib.sha256(row["request_text"].encode()).hexdigest(),
                "risk_score": row["score"],
                "status": status,
                "approval_channel": approval_channel,
                "approval_sender": approval_sender,
                "decided_at": decided_at,
            }
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            receipt_hash = hashlib.sha256((previous_hash + canonical).encode()).hexdigest()
            connection.execute(
                """
                INSERT INTO receipts (
                    request_id, payload_json, previous_hash, receipt_hash, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (request_id, canonical, previous_hash, receipt_hash, decided_at),
            )
            connection.execute(
                """
                UPDATE requests
                SET status = ?, decided_at = ?, approval_channel = ?,
                    approval_sender = ?, receipt_hash = ?
                WHERE request_id = ?
                """,
                (
                    status,
                    decided_at,
                    approval_channel,
                    approval_sender,
                    receipt_hash,
                    request_id,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._from_row(updated)

    def verify_chain(self) -> tuple[bool, int]:
        previous_hash = GENESIS_HASH
        count = 0
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM receipts ORDER BY sequence").fetchall()
        for row in rows:
            expected = hashlib.sha256((previous_hash + row["payload_json"]).encode()).hexdigest()
            if row["previous_hash"] != previous_hash or row["receipt_hash"] != expected:
                return False, count
            previous_hash = row["receipt_hash"]
            count += 1
        return True, count

    @staticmethod
    def _from_row(row: sqlite3.Row) -> StoredRequest:
        values: dict[str, Any] = dict(row)
        values["reasons"] = tuple(json.loads(values.pop("reasons_json")))
        return StoredRequest(**values)

    def export_request(self, request_id: str) -> dict[str, Any]:
        return asdict(self.get_request(request_id))
