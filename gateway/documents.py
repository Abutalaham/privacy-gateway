"""Bounded document extraction and short-lived, capability-protected sessions."""
from __future__ import annotations

import hashlib
import io
import secrets
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import config


class DocumentError(ValueError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class StoredDocument:
    document_id: str
    token_hash: str
    file_name: str
    size_bytes: int
    text: str
    created_at: float
    status: str = "uploaded"


def extract_document(filename: str, content: bytes) -> str:
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pdf", ".docx", ".txt"}:
        raise DocumentError("Unsupported file type. Upload a PDF, DOCX, or TXT file.", 415)
    if not content:
        raise DocumentError("The uploaded file is empty.")
    if len(content) > config.MAX_UPLOAD_BYTES:
        raise DocumentError("File exceeds the configured maximum upload size.", 413)

    try:
        if suffix == ".txt":
            text = content.decode("utf-8-sig")
            if "\x00" in text:
                raise DocumentError("The TXT file contains binary data.")
        elif suffix == ".pdf":
            if b"%PDF-" not in content[:1024]:
                raise DocumentError("The PDF file is invalid or corrupted.")
            try:
                from pypdf import PdfReader
            except ImportError as exc:
                raise DocumentError("PDF extraction support is unavailable. Install the project requirements.", 503) from exc

            reader = PdfReader(io.BytesIO(content), strict=True)
            if reader.is_encrypted:
                raise DocumentError("Password-protected PDF files are not supported.")
            if len(reader.pages) > config.MAX_DOCUMENT_PAGES:
                raise DocumentError("PDF exceeds the configured page limit.", 413)
            parts = []
            total_chars = 0
            for page in reader.pages:
                part = page.extract_text() or ""
                total_chars += len(part)
                if total_chars > config.MAX_DOCUMENT_CHARS:
                    raise DocumentError("Extracted text exceeds the configured document limit.", 413)
                parts.append(part)
            text = "\n".join(parts)
        else:
            if not content.startswith(b"PK"):
                raise DocumentError("The DOCX file is invalid or corrupted.")
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = archive.infolist()
                names = {member.filename for member in members}
                if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                    raise DocumentError("The DOCX file is invalid or corrupted.")
                if sum(member.file_size for member in members) > config.MAX_DOCUMENT_CHARS * 16:
                    raise DocumentError("DOCX contents exceed the configured extraction limit.", 413)
                if any(member.compress_size and member.file_size > member.compress_size * 200 for member in members):
                    raise DocumentError("DOCX compression ratio exceeds the safe processing limit.", 413)
            try:
                from docx import Document
            except ImportError as exc:
                raise DocumentError("DOCX extraction support is unavailable. Install the project requirements.", 503) from exc

            document = Document(io.BytesIO(content))
            sections = [paragraph.text for paragraph in document.paragraphs if paragraph.text]
            sections.extend(
                " | ".join(cell.text for cell in row.cells)
                for table in document.tables
                for row in table.rows
            )
            text = "\n".join(sections)
    except DocumentError:
        raise
    except UnicodeDecodeError as exc:
        raise DocumentError("The TXT file must use UTF-8 encoding.") from exc
    except Exception as exc:
        raise DocumentError(f"The {suffix[1:].upper()} file is invalid or corrupted.") from exc

    text = text.strip()
    if not text:
        raise DocumentError("No readable text was found in the document.")
    if len(text) > config.MAX_DOCUMENT_CHARS:
        raise DocumentError("Extracted text exceeds the configured document limit.", 413)
    return text


class DocumentStore:
    """In-memory document cache; access requires a random per-upload bearer token."""

    def __init__(self, ttl_seconds: Optional[int] = None, max_documents: Optional[int] = None):
        self.ttl_seconds = ttl_seconds or config.DOCUMENT_TTL_SECONDS
        self.max_documents = max_documents or config.MAX_ACTIVE_DOCUMENTS
        self._documents: Dict[str, StoredDocument] = {}
        self._lock = threading.RLock()
        self._stop_cleanup = threading.Event()
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_expired(self) -> None:
        interval = max(1, min(self.ttl_seconds / 10, 10))
        while not self._stop_cleanup.wait(interval):
            with self._lock:
                self._purge_expired(time.monotonic())

    def close(self) -> None:
        self._stop_cleanup.set()
        if self._cleanup_thread is not threading.current_thread():
            self._cleanup_thread.join(timeout=1)
        with self._lock:
            for document in self._documents.values():
                document.text = ""
            self._documents.clear()

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _purge_expired(self, now: float) -> None:
        expired = [
            document_id
            for document_id, document in self._documents.items()
            if now - document.created_at >= self.ttl_seconds
        ]
        for document_id in expired:
            self._documents[document_id].text = ""
            del self._documents[document_id]

    def create(self, filename: str, size_bytes: int, text: str) -> Tuple[StoredDocument, str]:
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        document = StoredDocument(
            document_id=uuid.uuid4().hex,
            token_hash=self._token_hash(token),
            file_name=Path(filename).name[:255],
            size_bytes=size_bytes,
            text=text,
            created_at=now,
        )
        with self._lock:
            self._purge_expired(now)
            if len(self._documents) >= self.max_documents:
                raise DocumentError("Document processing capacity is full. Try again shortly.", 503)
            self._documents[document.document_id] = document
        return document, token

    def get(self, document_id: str, token: str) -> StoredDocument:
        with self._lock:
            self._purge_expired(time.monotonic())
            document = self._documents.get(document_id)
            if (
                document is None
                or not token
                or not secrets.compare_digest(document.token_hash, self._token_hash(token))
            ):
                raise DocumentError("Document not found or access expired.", 404)
            return document

    def set_status(self, document_id: str, token: str, status: str) -> StoredDocument:
        with self._lock:
            document = self.get(document_id, token)
            if status == "processing" and document.status == "processing":
                raise DocumentError("This document is already being processed.", 409)
            document.status = status
            return document
