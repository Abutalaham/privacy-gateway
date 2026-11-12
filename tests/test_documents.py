import asyncio
import io
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import httpx
from docx import Document
from PIL import Image, ImageDraw, ImageFont

from gateway.audit import AuditLog, LEGACY_COLUMNS, hash_record
from gateway.detector import Detector, Entity
from gateway.documents import DocumentError, DocumentStore, HashedLineIndex, extract_document
from gateway.masking import Vault
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


def make_image(text: str = "Name: Rahul Sharma. Phone: 9876543210.") -> bytes:
    image = Image.new("RGB", (1000, 180), "white")
    ImageDraw.Draw(image).text((20, 40), text, fill="black", font=ImageFont.load_default())
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


class DocumentExtractionTests(unittest.TestCase):
    def test_extracts_supported_formats(self):
        self.assertIn("Rahul Sharma", extract_document("note.txt", b"My name is Rahul Sharma."))
        self.assertIn("Rahul Sharma", extract_document("note.docx", make_docx()))
        pdf_text = extract_document("note.pdf", make_pdf())
        self.assertIn("Rahul", pdf_text)
        self.assertIn("Sharma", pdf_text)

    def test_rejects_bad_formats_corrupt_files_and_oversize_uploads(self):
        with self.assertRaisesRegex(DocumentError, "Unsupported"):
            extract_document("photo.gif", b"not a document")
        with self.assertRaisesRegex(DocumentError, "corrupted"):
            extract_document("broken.pdf", b"%PDF- broken")
        with patch("gateway.config.MAX_UPLOAD_BYTES", 4):
            with self.assertRaisesRegex(DocumentError, "maximum"):
                extract_document("large.txt", b"12345")

    def test_extracts_image_text_with_local_ocr(self):
        image_bytes = make_image()
        with patch("gateway.documents._get_ocr_engine") as get_engine:
            get_engine.return_value.return_value = (
                [([[0, 0], [200, 0], [200, 30], [0, 30]], "Name: Rahul Sharma. Phone: 9876543210.", 0.99)],
                [],
            )
            text = extract_document("kyc.png", image_bytes)
        self.assertIn("Rahul Sharma", text)
        self.assertIn("9876543210", text)

    def test_scanned_pdf_uses_ocr_for_pages_without_extractable_text(self):
        scanned_pdf = make_pdf().replace(
            b"My name is Rahul Sharma", b" " * len(b"My name is Rahul Sharma")
        )
        with patch("gateway.documents._ocr_pdf_page", return_value="Name: Rahul Sharma."):
            self.assertIn("Rahul Sharma", extract_document("scan.pdf", scanned_pdf))

    def test_corrupted_image_is_rejected(self):
        with self.assertRaisesRegex(DocumentError, "invalid or corrupted"):
            extract_document("photo.png", b"\x89PNG\r\n\x1a\nnot-an-image")

    def test_hashed_index_matches_owner_to_account_field(self):
        text = (
            "Primary Account Holder Aarav Mehta Sole Signatory\n"
            "Bank Account Number 000123456789 Retail Savings Active\n"
            "Account Holder Priya Naik\n"
            "Bank Account Number 987654321012 Retail Savings Active\n"
        )
        index = HashedLineIndex(text)
        try:
            found = index.lookup_bank_account(text, "Give me Bank Account Number of Aarav Mehta")
            self.assertTrue(found.handled)
            self.assertEqual(found.status, "found")
            self.assertEqual(found.account_number, "000123456789")
            self.assertEqual(text[found.start:found.end], "000123456789")

            missing = index.lookup_bank_account(text, "Give me Bank Account Number of Rohan Das")
            self.assertEqual(missing.status, "not_found")

            unsupported = index.lookup_bank_account(text, "Summarize this document")
            self.assertFalse(unsupported.handled)
        finally:
            index.clear()

    def test_hashed_index_retrieves_only_question_relevant_lines(self):
        text = (
            "Full name Aarav Mehta\n"
            "Occupation Software Developer\n"
            "Email address aarav@example.com\n"
            "Mobile number +91 90000 12345\n"
            "Date of birth 14 February 1998\n"
        )
        index = HashedLineIndex(text)
        try:
            selected = index.retrieve_lines(text, "What is the occupation of Aarav Mehta?")
            self.assertLessEqual(len(selected), 3)
            self.assertIn("Occupation Software Developer", [text.splitlines()[line] for line in selected])
            self.assertNotIn("Email address aarav@example.com", [text.splitlines()[line] for line in selected])
            phone_lines = index.retrieve_lines(text, "What is Aarav Mehta's phone number?")
            self.assertIn("Mobile number +91 90000 12345", [text.splitlines()[line] for line in phone_lines])
        finally:
            index.clear()

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
    def test_uploaded_image_ocr_text_flows_through_pii_analysis(self):
        async def run():
            from gateway import api as api_module

            with tempfile.TemporaryDirectory() as temp_dir:
                test_gateway = build_default_gateway(
                    provider="mock",
                    fallback="none",
                    db_path=os.path.join(temp_dir, "audit.db"),
                    detector=Detector(use_presidio=False),
                )
                store = DocumentStore()
                self.addCleanup(store.close)
                ocr_result = (
                    [
                        ([[0, 0], [200, 0], [200, 30], [0, 30]], "Name: Rahul Sharma. PAN: ABCDE1234F.", 0.99),
                    ],
                    [],
                )
                transport = httpx.ASGITransport(app=api_module.app)
                with patch.object(api_module, "gateway", test_gateway), \
                        patch.object(api_module, "documents", store), \
                        patch("gateway.documents._get_ocr_engine") as get_engine:
                    get_engine.return_value.return_value = ocr_result
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        uploaded = await client.post(
                            "/v1/documents/upload",
                            files={"file": ("kyc.png", make_image(), "image/png")},
                        )
                        self.assertEqual(uploaded.status_code, 200, uploaded.text)
                        document = uploaded.json()
                        self.assertIn("Rahul Sharma", document["extracted_text"])
                        response = await client.post(
                            "/v1/documents/analyze",
                            headers={"Authorization": f"Bearer {document['access_token']}"},
                            json={"document_id": document["document_id"]},
                        )
                        self.assertEqual(response.status_code, 200, response.text)
                        analysis = response.json()
                        self.assertNotIn("Rahul", analysis["sanitized_text"])
                        self.assertNotIn("ABCDE1234F", analysis["sanitized_text"])
                        found = {(entity["label"], entity["value"]) for entity in analysis["entities"]}
                        self.assertIn(("PERSON", "Rahul Sharma"), found)
                        self.assertIn(("PAN", "ABCDE1234F"), found)

        asyncio.run(run())

    def test_analysis_table_only_contains_original_text_offsets(self):
        async def run():
            from gateway import api as api_module

            with tempfile.TemporaryDirectory() as temp_dir:
                store = DocumentStore()
                self.addCleanup(store.close)
                original_text = "user@example.com"
                original = Entity(
                    "EMAIL", 0, len(original_text), 0.99, original_text,
                    source="EmailRecognizer", placeholder="<EMAIL_1>", action="mask", pass_no=1,
                )
                recheck = Entity(
                    "PERSON", 1, 5, 0.8, "fake", source="recheck",
                    placeholder="<PERSON_1>", action="mask", pass_no=2,
                )
                fake_gateway = type("FakeGateway", (), {
                    "detector": type("FakeDetector", (), {"engine": "test"})(),
                    "sanitize": lambda self, text, purpose: (
                        [original, recheck], "<EMAIL_1>", Vault(), [], {},
                    ),
                })()
                transport = httpx.ASGITransport(app=api_module.app)
                with patch.object(api_module, "gateway", fake_gateway), patch.object(api_module, "documents", store):
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        uploaded = await client.post(
                            "/v1/documents/upload",
                            files={"file": ("profile.txt", original_text.encode(), "text/plain")},
                        )
                        self.assertEqual(uploaded.status_code, 200, uploaded.text)
                        data = uploaded.json()
                        response = await client.post(
                            "/v1/documents/analyze",
                            headers={"Authorization": f"Bearer {data['access_token']}"},
                            json={"document_id": data["document_id"]},
                        )
                        self.assertEqual(response.status_code, 200, response.text)
                        result = response.json()
                        self.assertEqual(result["entity_count"], 1)
                        self.assertEqual(len(result["entities"]), 1)
                        entity = result["entities"][0]
                        self.assertEqual(entity["pass"], 1)
                        self.assertEqual(original_text[entity["start"]:entity["end"]], entity["value"])

        asyncio.run(run())

    def test_extract_question_returns_only_relevant_lines(self):
        async def run():
            from gateway import api as api_module

            with tempfile.TemporaryDirectory() as temp_dir:
                test_gateway = build_default_gateway(
                    provider="mock",
                    fallback="none",
                    db_path=os.path.join(temp_dir, "audit.db"),
                    detector=Detector(use_presidio=False),
                )
                store = DocumentStore()
                self.addCleanup(store.close)
                transport = httpx.ASGITransport(app=api_module.app)
                with patch.object(api_module, "gateway", test_gateway), patch.object(api_module, "documents", store):
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        text = (
                            "Full name Aarav Mehta\n"
                            "Occupation Software Developer\n"
                            "Email address aarav@example.com\n"
                            "Date of birth 14 February 1998\n"
                            "Unrelated privacy-policy details fill this section.\n"
                        )
                        uploaded = await client.post(
                            "/v1/documents/upload",
                            files={"file": ("profile.txt", text.encode(), "text/plain")},
                        )
                        self.assertEqual(uploaded.status_code, 200, uploaded.text)
                        data = uploaded.json()
                        headers = {"Authorization": f"Bearer {data['access_token']}"}

                        processed = await client.post(
                            "/v1/documents/process",
                            headers=headers,
                            json={
                                "document_id": data["document_id"],
                                "task": "extract",
                                "instructions": "What is the occupation of Aarav Mehta?",
                                "provider": "mock",
                            },
                        )
                        self.assertEqual(processed.status_code, 200, processed.text)
                        result = processed.json()
                        self.assertIn("Occupation Software Developer", result["final_response"])
                        self.assertNotIn("aarav@example.com", result["final_response"])
                        self.assertNotIn("Unrelated privacy-policy details", result["final_response"])
                        self.assertLessEqual(len(result["final_response"].splitlines()), 3)
                        self.assertEqual(result["provider"], "local-evidence-index")
                        self.assertFalse(result["attempts"][0]["external"])

        asyncio.run(run())

    def test_account_question_uses_local_index_and_restores_masked_value(self):
        async def run():
            from gateway import api as api_module

            with tempfile.TemporaryDirectory() as temp_dir:
                test_gateway = build_default_gateway(
                    provider="mock",
                    fallback="none",
                    mock_mode="rotate",
                    db_path=os.path.join(temp_dir, "audit.db"),
                    detector=Detector(use_presidio=False),
                )
                store = DocumentStore()
                self.addCleanup(store.close)
                transport = httpx.ASGITransport(app=api_module.app)
                with patch.object(api_module, "gateway", test_gateway), patch.object(api_module, "documents", store):
                    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                        text = (
                            "Primary Account Holder Aarav Mehta Sole Signatory\n"
                            "Bank Account Number 000123456789 Retail Savings Active\n"
                        )
                        uploaded = await client.post(
                            "/v1/documents/upload",
                            files={"file": ("profile.txt", text.encode(), "text/plain")},
                        )
                        self.assertEqual(uploaded.status_code, 200, uploaded.text)
                        data = uploaded.json()
                        headers = {"Authorization": f"Bearer {data['access_token']}"}

                        processed = await client.post(
                            "/v1/documents/process",
                            headers=headers,
                            json={
                                "document_id": data["document_id"],
                                "instructions": "Give me Bank Account Number of Aarav Mehta",
                                "provider": "mock",
                            },
                        )
                        self.assertEqual(processed.status_code, 200, processed.text)
                        result = processed.json()
                        self.assertEqual(result["final_response"], "Bank account number: 000123456789.")
                        self.assertIn("<BANK_ACCOUNT_1>", result["llm_raw_response"])
                        self.assertNotIn("000123456789", result["outbound_payload"])
                        self.assertNotIn("Aarav Mehta", result["outbound_payload"])
                        self.assertEqual(result["provider"], "local-evidence-index")
                        self.assertFalse(result["attempts"][0]["external"])
                        self.assertNotIn("000123456789", str(test_gateway.audit.recent(1)))
                        self.assertTrue(test_gateway.audit.verify_chain())

        asyncio.run(run())

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
