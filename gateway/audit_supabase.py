"""Supabase Postgres-backed audit log using the server-side PostgREST API."""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import httpx

from .audit import COLUMNS, hash_record, serialize_record, verify_records


class SupabaseAuditLog:
    PAGE_SIZE = 1000
    APPEND_ATTEMPTS = 5

    def __init__(self, url: str, service_role_key: str, timeout: float = 30.0):
        if not url:
            raise ValueError("PG_SUPABASE_URL is required for the Supabase audit backend.")
        parsed_url = urlsplit(url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if not parsed_url.netloc or (
            parsed_url.scheme != "https" and parsed_url.hostname not in local_hosts
        ):
            raise ValueError("Supabase URL must use HTTPS, except for a local development URL.")
        if not service_role_key:
            raise ValueError("PG_SUPABASE_SERVICE_ROLE_KEY is required for the Supabase audit backend.")

        self._client = httpx.Client(
            base_url=f"{url.rstrip('/')}/rest/v1/",
            headers={
                "apikey": service_role_key,
                "Authorization": f"Bearer {service_role_key}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
        self._lock = threading.Lock()
        self._fetch({"select": "id", "limit": 0})

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if not response.is_success:
            detail = response.text.strip()[:500]
            raise RuntimeError(
                f"Supabase audit request failed with HTTP {response.status_code}: {detail}"
            )

    def _fetch(self, params: Dict[str, object]) -> List[dict]:
        response = self._client.get("audit_log", params=params)
        self._raise_for_status(response)
        records = response.json()
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise RuntimeError("Supabase returned an invalid audit-log response.")
        return records

    def _head_hash(self) -> str:
        latest = self._fetch({"select": "record_hash", "order": "id.desc", "limit": 1})
        return latest[0]["record_hash"] if latest else "GENESIS"

    @staticmethod
    def _is_chain_head_conflict(response: httpx.Response) -> bool:
        if response.status_code != 400:
            return False
        try:
            return response.json().get("code") == "40001"
        except (ValueError, AttributeError):
            return False

    def write(self, **rec) -> str:
        rec.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        row = serialize_record(rec)
        with self._lock:
            for _ in range(self.APPEND_ATTEMPTS):
                row["prev_hash"] = self._head_hash()
                row["record_hash"] = hash_record(row)
                response = self._client.post(
                    "rpc/append_audit_record",
                    json={"p_record": row},
                )
                if response.is_success:
                    return row["record_hash"]
                if self._is_chain_head_conflict(response):
                    continue
                self._raise_for_status(response)
        raise RuntimeError("Could not append the audit record because the chain changed repeatedly.")

    def recent(self, n: int = 50) -> List[dict]:
        return self._fetch({"select": "*", "order": "id.desc", "limit": max(0, n)})

    def get(self, request_id: str) -> Optional[dict]:
        records = self._fetch({
            "select": "*",
            "request_id": f"eq.{request_id}",
            "limit": 1,
        })
        return records[0] if records else None

    def verify_chain(self) -> bool:
        records: List[dict] = []
        offset = 0
        while True:
            page = self._fetch({
                "select": "*",
                "order": "id.asc",
                "offset": offset,
                "limit": self.PAGE_SIZE,
            })
            records.extend(page)
            if len(page) < self.PAGE_SIZE:
                return verify_records(records)
            offset += len(page)
