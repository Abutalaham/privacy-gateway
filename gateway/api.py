"""FastAPI service.  Run:  uvicorn gateway.api:app --port 8000"""
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import config
from .documents import DocumentError, DocumentStore, extract_document
from .llm import AllBackendsFailed
from .pipeline import LeakDetected, PolicyBlocked, build_default_gateway, build_default_router
from .policy import POLICIES

documents = DocumentStore()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    documents.close()


app = FastAPI(title="DPDP-Ready Privacy Gateway", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
gateway = build_default_gateway()


class ProcessIn(BaseModel):
    text: str
    task: Literal["summarize", "extract"] = "summarize"
    purpose: str = "default"
    doc_type: Optional[str] = None
    instructions: Optional[str] = None
    provider: Optional[str] = None


class DocumentAnalyzeIn(BaseModel):
    document_id: str
    purpose: str = "default"


class DocumentProcessIn(DocumentAnalyzeIn):
    task: Literal["summarize", "extract"] = "summarize"
    instructions: Optional[str] = None
    provider: Optional[str] = None


def _document_access(document_id: str, authorization: Optional[str]):
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(404, "Document not found or access expired.")
    try:
        return documents.get(document_id, token), token
    except DocumentError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc


def _router_for(provider: Optional[str]):
    if not provider or provider == config.LLM_PROVIDER:
        return gateway.router
    try:
        return build_default_router(provider)
    except ValueError as exc:
        raise HTTPException(422, "Unsupported AI provider.") from exc


@app.get("/health")
def health():
    return {"status": "ok", "detection_engine": gateway.detector.engine,
            "backends": [f"{b.name}:{b.model}" for b in gateway.router.backends],
            "max_upload_bytes": config.MAX_UPLOAD_BYTES}


@app.get("/v1/providers")
def providers():
    return {
        "default": config.LLM_PROVIDER.lower(),
        "providers": [
            {"id": "anthropic", "model": config.ANTHROPIC_MODEL, "available": bool(os.getenv("ANTHROPIC_API_KEY"))},
            {"id": "openai", "model": config.OPENAI_MODEL, "available": bool(os.getenv("OPENAI_API_KEY"))},
            {"id": "ollama", "model": config.OLLAMA_MODEL, "available": True},
            {"id": "local", "model": "rule-based-v1", "available": True},
            {"id": "mock", "model": "mock-llm-1", "available": True},
        ],
    }


@app.get("/v1/policies")
def policies():
    return {n: {"description": p.description, "actions": p.actions, "default": p.default_action} for n, p in POLICIES.items()}


@app.post("/v1/detect")
def detect(body: ProcessIn):
    """Stages 1-2 only: returns the sanitized text, nothing is sent anywhere."""
    ents, sanitized, _, blocked, tm = gateway.sanitize(body.text, body.purpose)
    if blocked:
        raise HTTPException(403, {"error": "blocked_by_policy", "labels": blocked})
    return {"sanitized_text": sanitized, "timings": tm, "detection_engine": gateway.detector.engine,
            "entities": [{"label": e.label, "placeholder": e.placeholder, "start": e.start, "end": e.end,
                          "score": round(e.score, 2)} for e in ents]}


@app.post("/v1/process")
def process(body: ProcessIn):
    try:
        r = gateway.process(body.text, task=body.task, purpose=body.purpose, doc_type=body.doc_type,
                            instructions=body.instructions, router=_router_for(body.provider))
    except KeyError as exc:
        raise HTTPException(422, "Unknown processing purpose.") from exc
    except PolicyBlocked as exc:
        raise HTTPException(403, {"error": "blocked_by_policy", "labels": exc.labels, "request_id": exc.request_id})
    except LeakDetected as exc:
        raise HTTPException(500, {"error": "leak_prevented", "request_id": exc.request_id})
    except AllBackendsFailed as exc:
        raise HTTPException(502, {"error": "llm_unavailable", "detail": str(exc)})
    return r.to_api()


@app.post("/v1/documents/upload")
async def upload_document(file: UploadFile = File(...)):
    try:
        content = await file.read(config.MAX_UPLOAD_BYTES + 1)
        if len(content) > config.MAX_UPLOAD_BYTES:
            raise DocumentError("File exceeds the configured maximum upload size.", 413)
        filename = file.filename or ""
        text = await run_in_threadpool(extract_document, filename, content)
        try:
            document, token = documents.create(filename, len(content), text)
        except DocumentError as exc:
            raise HTTPException(exc.status_code, str(exc)) from exc
        return {
            "document_id": document.document_id,
            "access_token": token,
            "file_name": document.file_name,
            "size_bytes": document.size_bytes,
            "extracted_text": document.text,
            "expires_in_seconds": documents.ttl_seconds,
            "status": document.status,
        }
    except DocumentError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    finally:
        await file.close()


@app.post("/v1/documents/analyze")
@app.post("/v1/documents/sanitize")
def analyze_document(body: DocumentAnalyzeIn, authorization: Optional[str] = Header(default=None)):
    document, token = _document_access(body.document_id, authorization)
    try:
        entities, sanitized, vault, blocked, timings = gateway.sanitize(document.text, body.purpose)
    except KeyError as exc:
        raise HTTPException(422, "Unknown processing purpose.") from exc
    try:
        if blocked:
            raise HTTPException(403, {"error": "blocked_by_policy", "labels": blocked})
        return {
            "document_id": document.document_id,
            "sanitized_text": sanitized,
            "detection_engine": gateway.detector.engine,
            "timings": timings,
            "entity_count": len(entities),
            "entities": [
                {"label": entity.label, "value": entity.text, "placeholder": entity.placeholder,
                 "start": entity.start, "end": entity.end, "score": round(entity.score, 3),
                 "action": entity.action, "source": entity.source, "pass": entity.pass_no}
                for entity in entities
            ],
        }
    finally:
        vault.wipe()


@app.get("/v1/documents/{document_id}/status")
def document_status(document_id: str, authorization: Optional[str] = Header(default=None)):
    document, _ = _document_access(document_id, authorization)
    return {
        "document_id": document.document_id,
        "file_name": document.file_name,
        "size_bytes": document.size_bytes,
        "status": document.status,
        "expires_in_seconds": max(0, int(documents.ttl_seconds - (time.monotonic() - document.created_at))),
    }


@app.post("/v1/documents/process")
def process_document(body: DocumentProcessIn, authorization: Optional[str] = Header(default=None)):
    document, token = _document_access(body.document_id, authorization)
    try:
        documents.set_status(document.document_id, token, "processing")
    except DocumentError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    try:
        r = gateway.process(
            document.text,
            task=body.task,
            purpose=body.purpose,
            doc_type=f"upload:{document.document_id}",
            instructions=body.instructions,
            document_id=document.document_id,
            router=_router_for(body.provider),
        )
    except PolicyBlocked as exc:
        documents.set_status(document.document_id, token, "blocked")
        raise HTTPException(403, {"error": "blocked_by_policy", "labels": exc.labels,
                                  "request_id": exc.request_id}) from exc
    except LeakDetected as exc:
        documents.set_status(document.document_id, token, "failed")
        raise HTTPException(500, {"error": "leak_prevented", "request_id": exc.request_id}) from exc
    except AllBackendsFailed as exc:
        documents.set_status(document.document_id, token, "failed")
        raise HTTPException(502, {"error": "llm_unavailable", "detail": "Configured AI providers are unavailable."}) from exc
    except HTTPException:
        documents.set_status(document.document_id, token, "failed")
        raise
    except KeyError as exc:
        documents.set_status(document.document_id, token, "failed")
        raise HTTPException(422, "Unknown processing purpose.") from exc
    except Exception:
        documents.set_status(document.document_id, token, "failed")
        raise
    documents.set_status(document.document_id, token, "complete")
    return r.to_api()


@app.get("/v1/audit")
def audit_list(limit: int = 50):
    return {"chain_valid": gateway.audit.verify_chain(), "records": gateway.audit.recent(limit)}


@app.get("/v1/audit/{request_id}")
def audit_one(request_id: str):
    rec = gateway.audit.get(request_id)
    if not rec:
        raise HTTPException(404, "unknown request_id")
    return rec


@app.get("/v1/metrics")
def metrics():
    """Return the evaluation report generated at reports/metrics.json."""
    report_path = Path(__file__).resolve().parent.parent / "reports" / "metrics.json"
    if not report_path.is_file():
        raise HTTPException(404, "Metrics report not found")
    with report_path.open(encoding="utf-8") as report:
        return json.load(report)
