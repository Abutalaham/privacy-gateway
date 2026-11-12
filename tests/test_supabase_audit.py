import json
import os
import sys
import unittest
from unittest.mock import patch

import httpx
from httpx import Client as HttpxClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.audit_supabase import SupabaseAuditLog  # noqa: E402


class SupabaseAuditLogTests(unittest.TestCase):
    def test_write_reads_and_verifies_hash_chain(self):
        records = []

        def handle(request):
            if request.method == "GET":
                query = request.url.params
                rows = list(records)
                if query.get("request_id", "").startswith("eq."):
                    request_id = query["request_id"][3:]
                    rows = [row for row in rows if row["request_id"] == request_id]
                rows.sort(key=lambda row: row["id"], reverse=query.get("order") == "id.desc")
                offset = int(query.get("offset", "0"))
                limit = int(query.get("limit", "1000"))
                return httpx.Response(200, json=rows[offset:offset + limit])

            body = json.loads(request.content)
            row = body["p_record"]
            head = records[-1]["record_hash"] if records else "GENESIS"
            if row["prev_hash"] != head:
                return httpx.Response(400, json={"code": "40001"})
            records.append({"id": len(records) + 1, **row})
            return httpx.Response(204)

        transport = httpx.MockTransport(handle)
        client_factory = lambda **kwargs: HttpxClient(transport=transport, **kwargs)
        with patch("gateway.audit_supabase.httpx.Client", side_effect=client_factory):
            audit = SupabaseAuditLog("https://example.supabase.co", "service-role-test-key")

        try:
            digest = audit.write(
                request_id="request-1",
                status="OK",
                entity_types={"PERSON": 1},
                outbound_payload='{"document":"<PERSON_1>"}',
            )
            audit.write(request_id="request-2", status="OK_FALLBACK", entity_types={})

            self.assertEqual(audit.get("request-1")["record_hash"], digest)
            self.assertEqual(len(audit.recent(1)), 1)
            self.assertTrue(audit.verify_chain())

            records[0]["outbound_payload"] = "tampered"
            self.assertFalse(audit.verify_chain())
        finally:
            audit._client.close()

    def test_requires_secure_url_and_server_key(self):
        with self.assertRaisesRegex(ValueError, "PG_SUPABASE_URL"):
            SupabaseAuditLog("", "service-role-test-key")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            SupabaseAuditLog("http://example.supabase.co", "service-role-test-key")
        with self.assertRaisesRegex(ValueError, "PG_SUPABASE_SERVICE_ROLE_KEY"):
            SupabaseAuditLog("https://example.supabase.co", "")


if __name__ == "__main__":
    unittest.main()
