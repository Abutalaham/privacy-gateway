"""Audit trail: one SQLite row per request, hash-chained so tampering is detectable.

Stored: detected entity types/counts, placeholder->type map, the EXACT outbound payload, SHA-256 of it,
model/provider used, every attempt (incl. failed + fallback), leak-check result, timings.
NOT stored: original PII values or the placeholder->value mapping.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import List, Optional

from . import config

LEGACY_COLUMNS = ["request_id", "created_at", "purpose", "doc_type", "task", "status", "entity_types", "placeholders",
           "provider", "model", "external", "fallback_used", "outbound_payload", "outbound_sha256",
           "leak_check", "attempts", "timings", "detection_engine", "error", "prev_hash", "record_hash"]
COLUMNS = LEGACY_COLUMNS[:1] + ["document_id"] + LEGACY_COLUMNS[1:]


def serialize_record(rec: dict) -> dict:
    return {
        column: (
            json.dumps(rec.get(column), ensure_ascii=False)
            if isinstance(rec.get(column), (dict, list))
            else ("" if rec.get(column) is None else str(rec.get(column)))
        )
        for column in COLUMNS
        if column not in ("prev_hash", "record_hash")
    }


def hash_record(row: dict) -> str:
    return hashlib.sha256((row["prev_hash"] + json.dumps(row, sort_keys=True)).encode()).hexdigest()


def verify_records(records: List[dict]) -> bool:
    prev = "GENESIS"
    for record in records:
        body = {column: record[column] for column in COLUMNS if column not in ("prev_hash", "record_hash")}
        body["prev_hash"] = prev
        valid_hash = hash_record(body) == record["record_hash"]
        if not valid_hash and not record.get("document_id"):
            legacy = {column: record[column] for column in LEGACY_COLUMNS if column not in ("prev_hash", "record_hash")}
            legacy["prev_hash"] = prev
            valid_hash = hash_record(legacy) == record["record_hash"]
        if record["prev_hash"] != prev or not valid_hash:
            return False
        prev = record["record_hash"]
    return True


class AuditLog:
    def __init__(self, path: str = config.DB_PATH):
        self.path, self._lock = path, threading.Lock()
        with self._conn() as c:
            c.execute(f"CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                      + ", ".join(f"{col} TEXT" for col in COLUMNS) + ")")
            columns = {row[1] for row in c.execute("PRAGMA table_info(audit_log)")}
            if "document_id" not in columns:
                c.execute("ALTER TABLE audit_log ADD COLUMN document_id TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def _conn(self):
        connection = sqlite3.connect(self.path, check_same_thread=False)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def write(self, **rec) -> str:
        rec.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        row = serialize_record(rec)
        with self._lock, self._conn() as c:
            last = c.execute("SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            row["prev_hash"] = last[0] if last else "GENESIS"
            row["record_hash"] = hash_record(row)
            c.execute(f"INSERT INTO audit_log ({','.join(COLUMNS)}) VALUES ({','.join('?' * len(COLUMNS))})",
                      [row[k] for k in COLUMNS])
        return row["record_hash"]

    def _rows(self, sql: str, args=()) -> List[dict]:
        with self._conn() as c:
            cur = c.execute(sql, args)
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]

    def recent(self, n: int = 50) -> List[dict]:
        return self._rows("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (n,))

    def get(self, request_id: str) -> Optional[dict]:
        rows = self._rows("SELECT * FROM audit_log WHERE request_id=?", (request_id,))
        return rows[0] if rows else None

    def verify_chain(self) -> bool:
        return verify_records(self._rows("SELECT * FROM audit_log ORDER BY id ASC"))


def build_audit_log(path: Optional[str] = None):
    if path is not None or config.AUDIT_BACKEND == "sqlite":
        return AuditLog(path or config.DB_PATH)
    if config.AUDIT_BACKEND == "supabase":
        from .audit_supabase import SupabaseAuditLog

        return SupabaseAuditLog(
            config.SUPABASE_URL,
            config.SUPABASE_SERVICE_ROLE_KEY,
            timeout=config.HTTP_TIMEOUT,
        )
    raise ValueError(f"Unknown audit backend '{config.AUDIT_BACKEND}'. Use 'sqlite' or 'supabase'.")
