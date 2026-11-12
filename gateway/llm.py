"""Stage 3 - Forward: pluggable LLM backends + router with automatic local fallback.

Every backend builds the EXACT request bytes first (`build_request`); the gateway scans and audits those
bytes, then sends the same bytes. So the audit record is byte-for-byte what left the organisation.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import config

SYSTEM_PROMPT = ("You process documents in which personal data was replaced by placeholders such as <PERSON_1>, "
                 "<AADHAAR_1>, <PAN_1>. Treat placeholders as opaque values. Whenever you refer to such a value, "
                 "copy the placeholder EXACTLY as written, including angle brackets. Never guess, invent or "
                 "alter placeholders and never try to infer the real values.")
TASK_PROMPTS = {
    "summarize": "Summarize the following document in 4-6 sentences.",
    "extract": ("Extract the key facts from the following document as compact JSON with keys: "
                "document_type, parties, identifiers, amounts, dates, issue_or_request."),
}


def build_prompt(sanitized: str, task: str, instructions: Optional[str]) -> str:
    head = instructions or TASK_PROMPTS.get(task, TASK_PROMPTS["summarize"])
    return f"{head}\n\n--- DOCUMENT START ---\n{sanitized}\n--- DOCUMENT END ---"


class BackendConfigError(RuntimeError):
    pass


@dataclass
class OutboundRequest:
    provider: str
    model: str
    url: str
    headers: dict
    body: bytes
    external: bool = True

    def body_text(self) -> str:
        return self.body.decode("utf-8")

    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class LLMBackend(ABC):
    name = "base"
    model = ""
    external = True

    @abstractmethod
    def build_request(self, sanitized: str, task: str, instructions: Optional[str]) -> OutboundRequest: ...

    @abstractmethod
    def parse(self, data: dict) -> str: ...

    def send(self, req: OutboundRequest) -> str:
        import httpx
        r = httpx.post(req.url, headers=req.headers, content=req.body, timeout=config.HTTP_TIMEOUT)
        r.raise_for_status()
        return self.parse(r.json())


def _need(value: Optional[str], what: str) -> str:
    if not value:
        raise BackendConfigError(f"{what} is not set")
    return value


class AnthropicBackend(LLMBackend):
    name, external = "anthropic", True

    def __init__(self, model: Optional[str] = None):
        self.model = model or config.ANTHROPIC_MODEL

    def build_request(self, sanitized, task, instructions):
        key = _need(os.getenv("ANTHROPIC_API_KEY"), "ANTHROPIC_API_KEY")
        body = {"model": self.model, "max_tokens": 800, "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": build_prompt(sanitized, task, instructions)}]}
        return OutboundRequest(self.name, self.model, "https://api.anthropic.com/v1/messages",
                               {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                               json.dumps(body, ensure_ascii=False).encode())

    def parse(self, data):
        return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")


class OpenAICompatBackend(LLMBackend):
    """OpenAI, Groq, Together, OpenRouter, Gemini's OpenAI endpoint ... anything speaking /chat/completions."""
    name, external = "openai-compatible", True

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        self.model = model or config.OPENAI_MODEL
        self.base_url = (base_url or config.OPENAI_BASE_URL).rstrip("/")

    def build_request(self, sanitized, task, instructions):
        key = _need(os.getenv("OPENAI_API_KEY"), "OPENAI_API_KEY")
        body = {"model": self.model, "temperature": 0,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": build_prompt(sanitized, task, instructions)}]}
        return OutboundRequest(self.name, self.model, f"{self.base_url}/chat/completions",
                               {"Authorization": f"Bearer {key}", "content-type": "application/json"},
                               json.dumps(body, ensure_ascii=False).encode())

    def parse(self, data):
        return data["choices"][0]["message"]["content"]


class OllamaBackend(LLMBackend):
    """Local SLM (runs on the organisation's own machine) - the fallback when the external LLM is down."""
    name, external = "ollama-local", False

    def __init__(self, model: Optional[str] = None):
        self.model = model or config.OLLAMA_MODEL

    def build_request(self, sanitized, task, instructions):
        body = {"model": self.model, "stream": False,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": build_prompt(sanitized, task, instructions)}]}
        return OutboundRequest(self.name, self.model, f"{config.OLLAMA_HOST}/api/chat",
                               {"content-type": "application/json"}, json.dumps(body, ensure_ascii=False).encode(), False)

    def parse(self, data):
        return data["message"]["content"]


class LocalExtractiveBackend(LLMBackend):
    """Zero-dependency last resort: extractive summary computed in-process. Gateway never goes fully down."""
    name, model, external = "local-extractive", "rule-based-v1", False

    def build_request(self, sanitized, task, instructions):
        body = {"task": task, "document": sanitized}
        return OutboundRequest(self.name, self.model, "inprocess://local-extractive", {},
                               json.dumps(body, ensure_ascii=False).encode(), False)

    def parse(self, data):
        return data

    def send(self, req):
        doc = json.loads(req.body)["document"]
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", doc) if len(s.strip()) > 15][:3]
        phs = list(dict.fromkeys(re.findall(r"<[A-Z_]+_\d+>", doc)))
        return "Summary (local fallback model): " + " ".join(sentences) + \
               ("\nEntities referenced: " + ", ".join(phs) if phs else "")


class MockBackend(LLMBackend):
    """Deterministic offline 'LLM' that deliberately paraphrases, reorders, drops and hallucinates placeholders.
    Used for the evaluation harness and for demoing without an API key."""
    name, model, external = "mock-external", "mock-llm-1", True
    MODES = ["faithful", "reorder", "paraphrase", "drop", "hallucinate"]

    def __init__(self, mode: str = "rotate", latency_ms: float = 0.0):
        self.mode, self.latency_ms, self.counter = mode, latency_ms, 0
        self.last_emitted: List[str] = []
        self.last_hallucinated: List[str] = []
        self.last_mode = ""

    def build_request(self, sanitized, task, instructions):
        body = {"model": self.model, "task": task, "instructions": instructions, "document": sanitized}
        return OutboundRequest(self.name, self.model, "https://mock.invalid/v1/complete",
                               {"content-type": "application/json"}, json.dumps(body, ensure_ascii=False).encode())

    def parse(self, data):
        return data

    def send(self, req):
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000)
        doc = json.loads(req.body)["document"]
        mode = self.MODES[self.counter % len(self.MODES)] if self.mode == "rotate" else self.mode
        self.counter += 1
        self.last_mode = mode
        rng = random.Random(int(req.sha256()[:8], 16))
        phs = list(dict.fromkeys(re.findall(r"<[A-Z_]+_\d+>", doc)))
        self.last_hallucinated = []

        def variant(ph, i):
            core = ph[1:-1]
            return [ph, f"[{core}]", core, f"< {core.lower()} >", f"<{core.lower()}>"][i % 5]

        if mode == "faithful":
            text = "Summary: " + doc[:500]
            self.last_emitted = list(dict.fromkeys(re.findall(r"<[A-Z_]+_\d+>", text)))
        elif mode == "reorder":
            lines = [l for l in re.split(r"\n+", doc) if l.strip()]
            text = "Key points (reordered):\n" + "\n".join(reversed(lines))
            self.last_emitted = phs
        elif mode == "drop":
            keep = [p for i, p in enumerate(phs) if i % 2 == 0]
            text = "The file is about " + (keep[0] if keep else "the customer") + ". Other details: " + \
                   ", ".join(keep[1:]) + ". Remaining data was omitted."
            self.last_emitted = keep
        else:
            order = list(reversed(phs))
            text = "Overview: identifiers noted - " + "; ".join(variant(p, i) + "'s record" if i % 3 == 2 else variant(p, i)
                                                           for i, p in enumerate(order)) + "."
            self.last_emitted = phs
            if mode == "hallucinate":
                self.last_hallucinated = ["<PERSON_9>", "<AADHAAR_7>"]
                text += " The document also mentions <PERSON_9> and Person 2, and <AADHAAR_7>."
        return text


# ----------------------------------------------------------------------------- router
@dataclass
class Attempt:
    provider: str
    model: str
    external: bool
    status: str = "pending"
    payload: str = ""
    payload_sha256: str = ""
    error: str = ""
    ms: float = 0.0


class AllBackendsFailed(RuntimeError):
    pass


class LLMRouter:
    """Primary backend first; on ANY failure (timeout, 5xx, missing key ...) fall through to local SLM(s)."""

    def __init__(self, backends: List[LLMBackend]):
        self.backends = backends

    def call(self, sanitized: str, task: str, instructions: Optional[str], verify: Callable[[str], None]):
        attempts: List[Attempt] = []
        for b in self.backends:
            att = Attempt(b.name, b.model, b.external)
            attempts.append(att)
            try:
                req = b.build_request(sanitized, task, instructions)
                att.payload, att.payload_sha256 = req.body_text(), req.sha256()
                verify(att.payload)                      # raises LeakDetected -> nothing is sent, not even locally
                t = time.perf_counter()
                text = b.send(req)
                att.ms, att.status = (time.perf_counter() - t) * 1000, "ok"
                return text, b, attempts
            except Exception as exc:
                if exc.__class__.__name__ == "LeakDetected":
                    att.status = "blocked"
                    raise
                att.status, att.error = "failed", f"{exc.__class__.__name__}: {exc}"[:300]
        raise AllBackendsFailed("; ".join(f"{a.provider}: {a.error}" for a in attempts))


def build_backend(name: str, mock_mode: str = "rotate") -> LLMBackend:
    name = (name or "mock").lower()
    return {"anthropic": lambda: AnthropicBackend(), "openai": lambda: OpenAICompatBackend(),
            "ollama": lambda: OllamaBackend(), "local": lambda: LocalExtractiveBackend()}.get(
        name, lambda: MockBackend(mock_mode))()
