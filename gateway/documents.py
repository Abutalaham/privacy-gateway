"""Bounded document extraction and short-lived, capability-protected sessions."""
from __future__ import annotations

import hashlib
import hmac
import io
import math
import re
import secrets
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import config

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
_OCR_ENGINE = None
_OCR_ENGINE_LOCK = threading.Lock()
_OCR_RUN_LOCK = threading.Lock()
_OCR_PAGE_TEXT_THRESHOLD = 30

_WORD = re.compile(r"[a-z0-9]+")
_BANK_ACCOUNT_QUESTION = re.compile(
    r"\b(?:bank\s+)?account(?:\s+(?:number|no\.?))?\b", re.IGNORECASE
)
_OWNER_RELATION = re.compile(
    r"\b(?:of|for|belonging\s+to|held\s+by|owned\s+by)\s+(.+)$", re.IGNORECASE
)
_ACCOUNT_FIELD = re.compile(
    r"\b(?:bank\s+account|account)\s+(?:number|no\.?)\s*[:#-]?\s*(\d{9,18})\b",
    re.IGNORECASE,
)
_QUESTION_STOP_WORDS = {
    "a", "an", "the", "customer", "client", "please", "in", "from", "whose",
    "is", "was", "me", "my", "of", "for", "number", "account", "bank",
}
_RETRIEVAL_STOP_WORDS = _QUESTION_STOP_WORDS | {
    "give", "show", "tell", "find", "get", "what", "which", "who", "when",
    "where", "why", "how", "does", "do", "did", "can", "could", "would",
    "should", "and", "or", "to", "with", "about", "document", "information",
    "details", "please", "his", "her", "their", "this", "that", "me",
}
_FIELD_QUERY_GROUPS = (
    {"occupation", "job", "role", "position"},
    {"email", "mail"},
    {"phone", "mobile", "telephone", "contact"},
    {"address", "residential", "residence", "location"},
    {"birth", "born", "dob", "date", "age"},
    {"name"},
    {"education", "qualification", "institution", "degree", "graduation"},
    {"company", "employer"},
    {"identity", "pan", "aadhaar", "passport"},
)


class DocumentError(ValueError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


def _get_ocr_engine():
    global _OCR_ENGINE
    with _OCR_ENGINE_LOCK:
        if _OCR_ENGINE is None:
            try:
                from rapidocr_onnxruntime import RapidOCR
                _OCR_ENGINE = RapidOCR()
            except Exception as exc:
                raise DocumentError(
                    "Local OCR is unavailable. Install the OCR dependencies from requirements.txt and retry.",
                    503,
                ) from exc
        return _OCR_ENGINE


def _ocr_image(image) -> str:
    try:
        import numpy as np
        from PIL import Image, ImageOps

        with Image.open(image) as opened:
            opened.verify()
        if hasattr(image, "seek"):
            image.seek(0)
        with Image.open(image) as opened:
            opened = ImageOps.exif_transpose(opened)
            if opened.width * opened.height > config.OCR_MAX_IMAGE_PIXELS:
                raise DocumentError("Image dimensions exceed the configured OCR limit.", 413)
            rgb_image = opened.convert("RGB")
            pixels = np.asarray(rgb_image)
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError("The uploaded image is invalid or corrupted.") from exc

    try:
        engine = _get_ocr_engine()
        with _OCR_RUN_LOCK:
            result, _ = engine(pixels)
        if result is None:
            return ""
        return "\n".join(
            str(line[1]).strip()
            for line in result
            if len(line) > 1 and str(line[1]).strip()
        )
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError("Local OCR could not read this image. Try a clearer, higher-resolution scan.") from exc


def _ocr_pdf_page(page) -> str:
    try:
        import pymupdf

        scale = min(2.0, 4000 / max(page.rect.width, page.rect.height))
        pixmap = page.get_pixmap(matrix=pymupdf.Matrix(scale, scale), alpha=False)
        if pixmap.width * pixmap.height > config.OCR_MAX_IMAGE_PIXELS:
            raise DocumentError("PDF page dimensions exceed the configured OCR limit.", 413)
        image_bytes = pixmap.tobytes("png")
        return _ocr_image(io.BytesIO(image_bytes))
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError("The scanned PDF page could not be rendered for local OCR.") from exc


def _docx_container_text(container) -> list[str]:
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    sections = []
    for block in container.iter_inner_content():
        if isinstance(block, Paragraph):
            if block.text.strip():
                sections.append(block.text)
        elif isinstance(block, Table):
            for row in block.rows:
                cells = [
                    " ".join(_docx_container_text(cell))
                    for cell in row.cells
                ]
                row_text = " | ".join(cell for cell in cells if cell)
                if row_text:
                    sections.append(row_text)
    return sections


@dataclass(frozen=True)
class EvidenceLookup:
    handled: bool
    status: str
    owner: Optional[str] = None
    account_number: Optional[str] = None
    start: Optional[int] = None
    end: Optional[int] = None


class HashedLineIndex:
    """Short-lived per-document inverted index keyed by HMACed normalized terms."""

    def __init__(self, text: str):
        self._key = bytearray(secrets.token_bytes(32))
        self._postings: Dict[bytes, set[int]] = {}
        self._line_offsets = []
        offset = 0
        lines = text.splitlines()
        raw_lines = text.splitlines(keepends=True)
        for line_number, raw_line in enumerate(raw_lines):
            line = raw_line.rstrip("\r\n")
            self._line_offsets.append(offset)
            for term in set(_WORD.findall(line.lower())):
                self._postings.setdefault(self._digest(term), set()).add(line_number)
            offset += len(raw_line)
        self.line_count = len(lines)

    def _digest(self, term: str) -> bytes:
        return hmac.new(bytes(self._key), term.encode("utf-8"), hashlib.sha256).digest()

    def clear(self) -> None:
        self._postings.clear()
        self._line_offsets.clear()
        self._key[:] = b"\x00" * len(self._key)
        self.line_count = 0

    def _matching_lines(self, terms: list[str]) -> set[int]:
        matches: set[int] = set()
        for term in terms:
            matches.update(self._postings.get(self._digest(term), ()))
        return matches

    def _line_contains_all(self, line_number: int, terms: list[str]) -> bool:
        return all(line_number in self._postings.get(self._digest(term), ()) for term in terms)

    def retrieve_lines(self, text: str, question: str, limit: int = 3) -> list[int]:
        terms = list(dict.fromkeys(
            word for word in _WORD.findall(question.lower())
            if len(word) > 1 and word not in _RETRIEVAL_STOP_WORDS
        ))
        if not terms:
            return []
        field_terms = set().union(*(
            group for group in _FIELD_QUERY_GROUPS if any(term in group for term in terms)
        ))
        if field_terms:
            terms = list(dict.fromkeys([term for term in terms if term in field_terms] + list(field_terms)))

        scores: Dict[int, float] = {}
        for term in terms:
            postings = self._postings.get(self._digest(term), ())
            if not postings:
                continue
            weight = 1 + math.log((self.line_count + 1) / (len(postings) + 1))
            for line_number in postings:
                scores[line_number] = scores.get(line_number, 0.0) + weight
        if not scores:
            return []

        ranked = sorted(scores, key=lambda line_number: (-scores[line_number], line_number))
        best_score = scores[ranked[0]]
        selected = [line_number for line_number in ranked if scores[line_number] >= best_score * 0.4][:limit]
        return sorted(selected)

    def lookup_bank_account(self, text: str, question: str) -> EvidenceLookup:
        if not _BANK_ACCOUNT_QUESTION.search(question):
            return EvidenceLookup(False, "unsupported")

        relation = _OWNER_RELATION.search(question)
        owner_terms = []
        if relation:
            for word in _WORD.findall(relation.group(1).lower()):
                if word in _QUESTION_STOP_WORDS:
                    break
                owner_terms.append(word)
                if len(owner_terms) == 4:
                    break
        if len(owner_terms) < 2:
            return EvidenceLookup(True, "owner_required")

        owner = " ".join(word.title() for word in owner_terms)
        lines = text.splitlines()
        query_lines = self._matching_lines(["bank", "account", "number", *owner_terms])
        candidates = []
        for line_number in sorted(query_lines):
            if line_number >= len(lines):
                continue
            match = _ACCOUNT_FIELD.search(lines[line_number])
            if not match:
                continue
            start = self._line_offsets[line_number] + match.start(1)
            end = start + len(match.group(1))
            nearby_owner_lines = [
                nearby for nearby in range(max(0, line_number - 2), min(len(lines), line_number + 3))
                if self._line_contains_all(nearby, owner_terms)
            ]
            if not nearby_owner_lines:
                continue
            distance = min(abs(nearby - line_number) for nearby in nearby_owner_lines)
            candidates.append((match.group(1), start, end, distance))

        distinct_values = {candidate[0] for candidate in candidates}
        if not distinct_values:
            return EvidenceLookup(True, "not_found", owner=owner)
        if len(distinct_values) != 1:
            return EvidenceLookup(True, "ambiguous", owner=owner)

        account_number = next(iter(distinct_values))
        _, start, end, _ = min(
            (candidate for candidate in candidates if candidate[0] == account_number),
            key=lambda candidate: candidate[3],
        )
        return EvidenceLookup(
            True, "found", owner=owner, account_number=account_number, start=start, end=end,
        )


@dataclass
class StoredDocument:
    document_id: str
    token_hash: str
    file_name: str
    size_bytes: int
    text: str
    created_at: float
    search_index: HashedLineIndex
    status: str = "uploaded"


def extract_document(filename: str, content: bytes) -> str:
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pdf", ".docx", ".txt"} | _IMAGE_SUFFIXES:
        raise DocumentError("Unsupported file type. Upload a PDF, DOCX, TXT, or image file.", 415)
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
            pdf_document = None
            try:
                parts = []
                total_chars = 0
                ocr_pages = 0
                for page_number, page in enumerate(reader.pages):
                    part = page.extract_text() or ""
                    if len(part.strip()) < _OCR_PAGE_TEXT_THRESHOLD:
                        ocr_pages += 1
                        if ocr_pages > config.OCR_MAX_PAGES:
                            raise DocumentError("Scanned PDF exceeds the configured OCR page limit.", 413)
                        if pdf_document is None:
                            try:
                                import pymupdf
                                pdf_document = pymupdf.open(stream=content, filetype="pdf")
                            except ImportError as exc:
                                raise DocumentError(
                                    "Scanned PDF support is unavailable. Install the project requirements.",
                                    503,
                                ) from exc
                            except Exception as exc:
                                raise DocumentError("The PDF could not be rendered for OCR.") from exc
                        ocr_text = _ocr_pdf_page(pdf_document.load_page(page_number))
                        if ocr_text:
                            part = ocr_text
                    total_chars += len(part)
                    if total_chars > config.MAX_DOCUMENT_CHARS:
                        raise DocumentError("Extracted text exceeds the configured document limit.", 413)
                    parts.append(part)
                text = "\n".join(parts)
            finally:
                if pdf_document is not None:
                    pdf_document.close()
        elif suffix in _IMAGE_SUFFIXES:
            text = _ocr_image(io.BytesIO(content))
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
            sections = _docx_container_text(document)
            seen_parts = set()
            for section in document.sections:
                for part in (section.header, section.footer):
                    part_name = str(part.part.partname)
                    if part_name not in seen_parts:
                        seen_parts.add(part_name)
                        sections.extend(_docx_container_text(part))
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
                document.search_index.clear()
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
            self._documents[document_id].search_index.clear()
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
            search_index=HashedLineIndex(text),
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
