"""Stage 1 - Detect.

Primary engine : Microsoft Presidio AnalyzerEngine with
                 - India PatternRecognizers (Aadhaar, PAN, GSTIN, Voter ID, Passport, phone, e-mail)
                 - rule recognizers for Indian / code-mixed names and addresses
                 - spaCy NER (PERSON) and optional GLiNER (PERSON + ADDRESS) - both run locally
Fallback engine: identical specs executed with plain `re` (only used if Presidio is not installed,
                 so the project always runs; the active engine is exposed as `Detector.engine`).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from . import config
from .ner_rules import find_addresses, find_names
from .recognizers import ENTITY_TO_LABEL, LABEL_CONTEXT, NEGATIVE_CONTEXT, SPECS

log = logging.getLogger("privacy_gateway.detector")
ID_LABELS = {"AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT", "PHONE"}


@dataclass
class Entity:
    label: str
    start: int
    end: int
    score: float
    text: str
    source: str = "presidio"
    placeholder: str = ""
    action: str = ""
    forced_placeholder: Optional[str] = None
    pass_no: int = 1


# ----------------------------------------------------------------------------- GLiNER (optional)
class GlinerFinder:
    LABELS = {"person name": "PERSON", "postal address": "ADDRESS"}

    def __init__(self):
        from gliner import GLiNER  # type: ignore
        self.model = GLiNER.from_pretrained(config.GLINER_MODEL)

    def __call__(self, text: str):
        out, pos = [], 0
        for chunk in re.findall(r"[^\n]+\n?|\n", text):          # chunk by line: GLiNER has a ~384 token window
            if chunk.strip():
                for p in self.model.predict_entities(chunk, list(self.LABELS), threshold=0.5):
                    out.append((self.LABELS[p["label"]], pos + p["start"], pos + p["end"], float(p["score"])))
            pos += len(chunk)
        return out


# ----------------------------------------------------------------------------- Presidio engine
def build_presidio_analyzer(gliner: Optional[GlinerFinder]):
    from presidio_analyzer import (AnalyzerEngine, EntityRecognizer, Pattern, PatternRecognizer,
                                   RecognizerRegistry, RecognizerResult)
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    class IndiaPatternRecognizer(PatternRecognizer):
        def __init__(self, spec):
            super().__init__(supported_entity=spec.entity, name=f"{spec.entity}_recognizer",
                             patterns=[Pattern(n, rx, sc) for n, rx, sc in spec.patterns],
                             context=spec.context, supported_language="en")
            self._validator = spec.validator

        def validate_result(self, pattern_text):
            # True -> checksum/format valid -> score 1.0 ; None -> unknown (keep pattern score)
            return True if self._validator and self._validator(pattern_text) else None

    class FunctionRecognizer(EntityRecognizer):
        def __init__(self, entities, finder, name):
            super().__init__(supported_entities=entities, name=name, supported_language="en")
            self._finder = finder

        def load(self):
            pass

        def analyze(self, text, entities, nlp_artifacts=None):
            return [RecognizerResult(entity_type=t, start=s, end=e, score=sc) for t, s, e, sc in self._finder(text)]

    registry = RecognizerRegistry()
    registry.supported_languages = ["en"]
    for spec in SPECS:
        registry.add_recognizer(IndiaPatternRecognizer(spec))
    registry.add_recognizer(FunctionRecognizer(["PERSON"], find_names, "IndianNameRules"))
    registry.add_recognizer(FunctionRecognizer(["ADDRESS"], find_addresses, "IndianAddressRules"))
    if gliner:
        registry.add_recognizer(FunctionRecognizer(["PERSON", "ADDRESS"], gliner, "GLiNER"))
    nlp = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": config.SPACY_MODEL}]}).create_engine()
    try:                                   # statistical NER for names (low score: rules/GLiNER dominate)
        from presidio_analyzer.predefined_recognizers import SpacyRecognizer
        registry.add_recognizer(SpacyRecognizer(supported_entities=["PERSON"], ner_strength=0.5))
    except Exception as exc:               # pragma: no cover
        log.warning("SpacyRecognizer unavailable: %s", exc)
    return AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en"])


# ----------------------------------------------------------------------------- fallback engine
def _prefix(text: str, start: int, n: int = 40) -> str:
    """Text just before a match, on the SAME line only (context must not leak across lines)."""
    return text[max(0, start - n):start].split("\n")[-1].lower()


def _last_pos(window: str, words) -> int:
    return max((window.rfind(w) for w in words), default=-1)


def _context_hit(text: str, start: int, label: str) -> bool:
    return _last_pos(_prefix(text, start), LABEL_CONTEXT.get(label, [])) >= 0


def _negated(text: str, start: int, label: str) -> bool:
    """True if a 'this is a txn/policy/claim number' word sits closer to the match than any identity keyword."""
    w = _prefix(text, start, 30)
    return _last_pos(w, NEGATIVE_CONTEXT) > _last_pos(w, LABEL_CONTEXT.get(label, []))


def _fallback_analyze(text: str, gliner: Optional[GlinerFinder]):
    res = []
    for spec in SPECS:
        for _, rx, base in spec.patterns:
            for m in re.finditer(rx, text, re.I | re.S):
                score = 1.0 if spec.validator and spec.validator(m.group()) else base
                if score < 1.0 and _context_hit(text, m.start(), spec.label):
                    score = max(score + 0.35, 0.4)
                res.append((spec.label, m.start(), m.end(), min(score, 1.0), "regex"))
    for finder, src in ((find_names, "rules"), (find_addresses, "rules"), (gliner, "gliner")):
        if finder:
            res += [(*r, src) for r in finder(text)]
    return res


# ----------------------------------------------------------------------------- public API
class Detector:
    def __init__(self, use_presidio: bool = config.USE_PRESIDIO, use_gliner: bool = config.USE_GLINER):
        self.gliner = None
        if use_gliner:
            try:
                self.gliner = GlinerFinder()
            except Exception as exc:
                log.warning("GLiNER not available (%s) - continuing without it", exc)
        self.analyzer = None
        self.engine = "builtin-regex"
        if use_presidio:
            try:
                self.analyzer = build_presidio_analyzer(self.gliner)
                self.engine = "presidio"
            except Exception as exc:
                log.warning("Presidio engine unavailable (%s) - using built-in fallback engine", exc)

    def _raw(self, text: str):
        if self.analyzer is not None:
            out = []
            for r in self.analyzer.analyze(text=text, language="en", score_threshold=config.SCORE_THRESHOLD):
                label = ENTITY_TO_LABEL.get(r.entity_type)
                if not label:
                    continue
                src = (r.recognition_metadata or {}).get("recognizer_name", "presidio") if r.recognition_metadata else "presidio"
                out.append((label, r.start, r.end, float(r.score), str(src)))
            return out
        return [r for r in _fallback_analyze(text, self.gliner) if r[3] >= config.SCORE_THRESHOLD]

    def detect(self, text: str) -> List[Entity]:
        cands = []
        for label, s, e, score, src in self._raw(text):
            span = text[s:e]
            if label == "PERSON" and "SpacyRecognizer" in src:
                if any(w.lower() in __import__("gateway.ner_rules", fromlist=["STOP"]).STOP for w in span.split()):
                    continue
            if label in ID_LABELS and score < 0.9 and _negated(text, s, label):
                continue                                       # e.g. "UTR 402312345678", "Policy POL1234567"
            cands.append(Entity(label, s, e, score, span, src))
        return resolve_overlaps(cands)


def resolve_overlaps(ents: List[Entity]) -> List[Entity]:
    """Greedy: highest score, then longest span wins; overlapping losers are dropped."""
    chosen: List[Entity] = []
    for e in sorted(ents, key=lambda x: (-x.score, -(x.end - x.start), x.start)):
        if all(e.end <= c.start or e.start >= c.end for c in chosen):
            chosen.append(e)
    return sorted(chosen, key=lambda x: x.start)
