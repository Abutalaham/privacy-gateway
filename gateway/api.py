"""FastAPI service.  Run:  uvicorn gateway.api:app --port 8000"""
import json
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .llm import AllBackendsFailed
from .pipeline import LeakDetected, PolicyBlocked, build_default_gateway
from .policy import POLICIES

app = FastAPI(title="DPDP-Ready Privacy Gateway", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


@app.get("/health")
def health():
    return {"status": "ok", "detection_engine": gateway.detector.engine,
            "backends": [f"{b.name}:{b.model}" for b in gateway.router.backends]}


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
                            instructions=body.instructions)
    except PolicyBlocked as exc:
        raise HTTPException(403, {"error": "blocked_by_policy", "labels": exc.labels, "request_id": exc.request_id})
    except LeakDetected as exc:
        raise HTTPException(500, {"error": "leak_prevented", "request_id": exc.request_id})
    except AllBackendsFailed as exc:
        raise HTTPException(502, {"error": "llm_unavailable", "detail": str(exc)})
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
