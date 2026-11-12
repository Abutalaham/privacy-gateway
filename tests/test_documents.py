import asyncio
import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import httpx
from docx import Document

from gateway.audit import AuditLog, LEGACY_COLUMNS, hash_record
from gateway.detector import Detector
from gateway.documents import DocumentError, DocumentStore, extract_document
from gateway.pipeline import build_default_gateway


def make_pdf() -> bytes:
    stream = b"BT /F1 12 Tf 30 100 Td (My name is Rahul Sharma) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    )
    return bytes(output)


def make_docx() -> bytes:
    document = Document()
    document.add_paragraph("My name is Rahul Sharma.")
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


class DocumentExtractionTests(unittest.TestCase):
    def test_extracts_supported_formats(self):
        self.assertIn("Rahul Sharma", extract_document("note.txt", b"My name is Rahul Sharma."))
        self.assertIn("Rahul Sharma", extract_document("note.docx", make_docx()))
        self.assertIn("Rahul Sharma", extract_document("note.pdf", make_pdf()))

    def test_rejects_bad_formats_corrupt_files_and_oversize_uploads(self):
        with self.assertRaisesRegex(DocumentError, "Unsupported"):
            extract_document("photo.png", b"not a document")
        with self.assertRaisesRegex(DocumentError, "corrupted"):
            extract_document("broken.pdf", b"%PDF- broken")
        with patch("gateway.config.MAX_UPLOAD_BYTES", 4):
            with self.assertRaisesRegex(DocumentError, "maximum"):
                extract_document("large.txt", b"12345")

    def test_document_access_token_is_scoped_and_expires(self):
        store = DocumentStore(ttl_seconds=60, max_documents=2)
        self.addCleanup(store.close)
        first, first_token = store.create("one.txt", 1, "one")
        second, _ = store.create("two.txt", 1, "two")
        with self.assertRaisesRegex(DocumentError, "not found"):
            store.get(first.document_id, "wrong-token")
        with self.assertRaisesRegex(DocumentError, "not found"):
            store.get(second.document_id, first_token)
        self.assertEqual(store.get(first.document_id, first_token).text, "one")

    def test_expired_document_cannot_be_accessed(self):
        store = DocumentStore(ttl_seconds=1, max_documents=1)
        self.addCleanup(store.close)
        document, token = store.create("one.txt", 1, "sensitive")
        document.created_at -= 2
        with self.assertRaisesRegex(DocumentError, "expired"):
            store.get(document.document_id, token)


class AuditUpgradeTests(unittest.TestCase):
    def test_adds_document_id_without_breaking_existing_hash_chain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "audit.db")
            old_record = {
                column: "" for column in LEGACY_COLUMNS
                if column not in ("prev_hash", "record_hash")
            }
            old_record["request_id"] = "legacy-request"
            old_record["prev_hash"] = "GENESIS"
            old_record["record_hash"] = hash_record(old_record)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    + ", ".join(f"{column} TEXT" for column in LEGACY_COLUMNS)
                    + ")"
                )
                connection.execute(
                    f"INSERT INTO audit_log ({','.join(LEGACY_COLUMNS)}) "
                    f"VALUES ({','.join('?' for _ in LEGACY_COLUMNS)})",
                    [old_record[column] for column in LEGACY_COLUMNS],
                )
                connection.commit()
            finally:
                connection.close()

            audit = AuditLog(path)
            self.assertTrue(audit.verify_chain())
            audit.write(request_id="new-request", document_id="opaque-doc", status="OK")
            self.assertTrue(audit.verify_chain())


class DocumentApiTests(unittest.TestCase):
    def test_upload_review_process_and_audit(self):
        async def run():
            from gateway import api as api_module

            with tempfile.TemporaryDirectory() as temp_dir:
                test_gateway = build_default_gateway(
                    provider="mock",
                    fallback="none",
                    mock_mode="faithful",
                    db_path=os.path.join(temp_dir, "audit.db"),
                    detector=Detector(use_presidio=False),
                )
                store = DocumentStore()
                self.addCleanup(store.close)
                transport = httpx.ASGITransport(app=api_module.app)
                with patch.object(api_module, "gateway", test_gateway), patch.object(api_module, "documents", store):
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        uploaded = await client.post(
                            "/v1/documents/upload",
                            files={"file": ("profile.txt", b"My name is Rahul Sharma. Email: rahul@example.com.", "text/plain")},
                        )
                        self.assertEqual(uploaded.status_code, 200, uploaded.text)
                        upload_data = uploaded.json()
                        doc_id, token = upload_data["document_id"], upload_data["access_token"]
                        self.assertEqual(upload_data["extracted_text"], "My name is Rahul Sharma. Email: rahul@example.com.")

                        denied = await client.post(
                            "/v1/documents/analyze",
                            json={"document_id": doc_id},
                        )
                        self.assertEqual(denied.status_code, 404)

                        headers = {"Authorization": f"Bearer {token}"}
                        analysis = await client.post(
                            "/v1/documents/analyze",
                            headers=headers,
                            json={"document_id": doc_id, "purpose": "default"},
                        )
                        self.assertEqual(analysis.status_code, 200, analysis.text)
                        self.assertIn("<PERSON_1>", analysis.json()["sanitized_text"])
                        self.assertIn("Rahul Sharma", [entity["value"] for entity in analysis.json()["entities"]])
                        self.assertEqual(analysis.json()["entity_count"], 2)

                        processed = await client.post(
                            "/v1/documents/process",
                            headers=headers,
                            json={"document_id": doc_id, "purpose": "default", "task": "summarize", "provider": "mock"},
                        )
                        self.assertEqual(processed.status_code, 200, processed.text)
                        result = processed.json()
                        self.assertEqual(result["sanitized_text"], analysis.json()["sanitized_text"])
                        self.assertIn("Rahul Sharma", result["final_response"])
                        self.assertNotIn("Rahul Sharma", result["outbound_payload"])
                        self.assertNotIn("rahul@example.com", result["outbound_payload"])
                        self.assertNotIn("mapping", result)

                        audit_record = test_gateway.audit.get(result["request_id"])
                        self.assertEqual(audit_record["document_id"], doc_id)
                        self.assertNotIn("Rahul Sharma", str(audit_record))
                        self.assertTrue(test_gateway.audit.verify_chain())
                        status = await client.get(f"/v1/documents/{doc_id}/status", headers=headers)
                        self.assertEqual(status.json()["status"], "complete")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main(verbosity=2)
