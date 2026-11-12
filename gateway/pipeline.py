"""PrivacyGateway: Detect -> Mask -> (verify) -> Forward -> Reinsert -> Audit."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import config
from .audit import AuditLog, build_audit_log
from .detector import Detector, Entity, resolve_overlaps
from .llm import AllBackendsFailed, LLMRouter
from .masking import Vault, apply_masks
from .policy import get_policy
from .reinsert import ReinsertResult, reinsert


class PolicyBlocked(Exception):
    def __init__(self, labels, request_id):
        super().__init__(f"Blocked by privacy policy: {', '.join(labels)}")
        self.labels, self.request_id = labels, request_id


class LeakDetected(Exception):
    def __init__(self, leaks, request_id=""):
        super().__init__(f"{len(leaks)} raw PII value(s) found in outbound payload - request blocked")
        self.leaks, self.request_id = leaks, request_id


@dataclass
class GatewayResult:
    request_id: str
    purpose: str
    original_text: str
    sanitized_text: str
    outbound_payload: str
    entities: List[dict]
    llm_raw_response: str
    final_response: str
    provider: str
    model: str
    fallback_used: bool
    attempts: List[dict]
    leak_check: dict
    reinsertion: dict
    timings: Dict[str, float]
    detection_engine: str
    mapping: Dict[str, str] = field(default_factory=dict, repr=False)   # LOCAL ONLY - never audited / never in API output

    def to_api(self, include_values: bool = False) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("mapping", "original_text")}
        if include_values:
            d["mapping"] = self.mapping
        return d


class PrivacyGateway:
    MAX_ROUNDS = 3

    def __init__(self, detector: Detector, router: LLMRouter, audit: AuditLog):
        self.detector, self.router, self.audit = detector, router, audit

    # ---- Stage 1 + 2 ---------------------------------------------------------------
    def sanitize(self, text: str, purpose: str = "default"):
        policy = get_policy(purpose)
        t = time.perf_counter()
        ents = self.detector.detect(text)
        t_detect = (time.perf_counter() - t) * 1000
        blocked = sorted({e.label for e in ents if policy.action(e.label) == "block"})
        vault = Vault()
        if blocked:
            return ents, None, vault, blocked, {"detect_ms": t_detect, "mask_ms": 0.0}
        t = time.perf_counter()
        sanitized = apply_masks(text, ents, policy, vault)
        extra_all: List[Entity] = []
        for _ in range(self.MAX_ROUNDS):                      # defence in depth: re-scan our own output
            spans = vault.token_spans(sanitized)
            again = [e for e in self.detector.detect(sanitized)
                     if not any(e.start < b and e.end > a for a, b in spans)]
            again = resolve_overlaps(again + vault.residual_entities(sanitized))
            if not again:
                break
            for e in again:
                e.pass_no, e.source = 2, e.source + "+recheck"
            if any(policy.action(e.label) == "block" for e in again):
                return ents, None, vault, sorted({e.label for e in again if policy.action(e.label) == "block"}), \
                    {"detect_ms": t_detect, "mask_ms": 0.0}
            sanitized = apply_masks(sanitized, again, policy, vault)
            extra_all += again
        t_mask = (time.perf_counter() - t) * 1000
        return ents + extra_all, sanitized, vault, [], {"detect_ms": t_detect, "mask_ms": t_mask}

    # ---- full request --------------------------------------------------------------
    def process(self, text: str, *, task: str = "summarize", purpose: str = "default",
                doc_type: Optional[str] = None, instructions: Optional[str] = None) -> GatewayResult:
        rid, t0 = uuid.uuid4().hex[:12], time.perf_counter()
        base = dict(request_id=rid, purpose=purpose, doc_type=doc_type, task=task, detection_engine=self.detector.engine)
        ents, sanitized, vault, blocked, tm = self.sanitize(text, purpose)
        counts: Dict[str, int] = {}
        for e in ents:
            counts[e.label] = counts.get(e.label, 0) + 1
        if blocked:
            self.audit.write(**base, status="BLOCKED_BY_POLICY", entity_types=counts, error=f"blocked labels: {blocked}",
                             leak_check={"checked": 0, "leaks": 0}, outbound_payload="(nothing sent)")
            raise PolicyBlocked(blocked, rid)

        def verify(body: str):
            leaks = vault.leaks_in(body)
            if leaks:
                raise LeakDetected(leaks, rid)

        t = time.perf_counter()
        try:
            llm_text, backend, attempts = self.router.call(sanitized, task, instructions, verify)
        except LeakDetected as exc:
            self.audit.write(**base, status="BLOCKED_LEAK", entity_types=counts, error=str(exc),
                             leak_check={"leaks": len(exc.leaks)}, outbound_payload="(blocked before sending)")
            raise
        except AllBackendsFailed as exc:
            self.audit.write(**base, status="LLM_UNAVAILABLE", entity_types=counts, error=str(exc),
                             leak_check={"leaks": 0}, outbound_payload=sanitized)
            raise
        t_llm = (time.perf_counter() - t) * 1000

        t = time.perf_counter()
        rr: ReinsertResult = reinsert(llm_text, vault)
        t_re = (time.perf_counter() - t) * 1000

        used = attempts[-1]
        mapping = {p: v for p, v in vault.ph2val.items()}
        timings = {**tm, "llm_ms": t_llm, "reinsert_ms": t_re}
        entity_report = [{"label": e.label, "placeholder": e.placeholder, "action": e.action, "start": e.start,
                          "end": e.end, "score": round(e.score, 2), "source": e.source, "pass": e.pass_no} for e in ents]
        leak_check = {"values_checked": len(vault.originals()), "leaks": 0, "outbound_sha256": used.payload_sha256}
        status = "OK_FALLBACK" if len(attempts) > 1 else "OK"
        t = time.perf_counter()
        self.audit.write(**base, status=status, entity_types=counts,
                         placeholders={p: vault.ph2label[p] for p in vault.ph2val},
                         provider=used.provider, model=used.model, external=used.external,
                         fallback_used=len(attempts) > 1, outbound_payload=used.payload,
                         outbound_sha256=used.payload_sha256, leak_check=leak_check,
                         attempts=[a.__dict__ for a in attempts], timings=timings)
        timings["audit_ms"] = (time.perf_counter() - t) * 1000
        timings["total_ms"] = (time.perf_counter() - t0) * 1000
        timings["gateway_overhead_ms"] = timings["total_ms"] - t_llm
        result = GatewayResult(rid, purpose, text, sanitized, used.payload, entity_report, llm_text, rr.text,
                               used.provider, used.model, len(attempts) > 1, [a.__dict__ for a in attempts],
                               leak_check, {"restored": rr.restored, "unresolved": rr.unresolved, "dropped": rr.dropped},
                               timings, self.detector.engine, mapping)
        vault.wipe()                                          # mapping only survives in `result.mapping` for the caller
        return result


def build_default_gateway(provider: Optional[str] = None, fallback: Optional[str] = None,
                          mock_mode: str = "rotate", db_path: Optional[str] = None,
                          detector: Optional[Detector] = None) -> PrivacyGateway:
    from .llm import LocalExtractiveBackend, OllamaBackend, build_backend
    chain = [build_backend(provider or config.LLM_PROVIDER, mock_mode)]
    fb = (fallback or config.FALLBACK).lower()
    if fb == "ollama":
        chain += [OllamaBackend(), LocalExtractiveBackend()]
    elif fb == "local":
        chain += [LocalExtractiveBackend()]
    audit = AuditLog(db_path) if db_path is not None else build_audit_log()
    return PrivacyGateway(detector or Detector(), LLMRouter(chain), audit)
