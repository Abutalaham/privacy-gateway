"""Stage 2 - Mask: consistent typed placeholders + the secure in-memory vault.

Design rules
  * numbering follows first occurrence in the document; same value (normalised) => same placeholder
  * the vault lives only in process memory for ONE request and is wiped afterwards (never written to the audit DB)
  * ambiguous partial names (e.g. "Sharma" when two Sharmas exist) get their OWN placeholder, never a guess
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple

from .detector import Entity

TOKEN_RE = re.compile(r"<[A-Z_]+_\d+>|\[REDACTED_[A-Z_]+\]")


def _alnum(s: str) -> str:
    return re.sub(r"[^0-9a-z]", "", s.lower())


class Vault:
    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.key2ph: Dict[Tuple[str, str], str] = {}
        self.ph2val: Dict[str, str] = {}
        self.ph2label: Dict[str, str] = {}
        self.fpe: Dict[str, str] = {}                 # fake token -> original (format-preserving mode)
        self.redacted: List[Tuple[str, str]] = []     # values removed irreversibly (still leak-checked)
        self._key = os.urandom(32)                    # per-request FPE key, never stored

    # -- normalisation -----------------------------------------------------------
    @staticmethod
    def _norm(label: str, value: str) -> str:
        if label in ("PERSON", "ADDRESS"):
            return re.sub(r"[^\w ]", "", re.sub(r"\s+", " ", value.casefold())).strip()
        return _alnum(value)

    def _person_alias(self, norm: str):
        """Single token that is part of exactly ONE known person -> same placeholder; otherwise no alias."""
        if " " in norm:
            return None
        hits = {ph for (lab, k), ph in self.key2ph.items() if lab == "PERSON" and " " in k and norm in k.split()}
        return hits.pop() if len(hits) == 1 else None

    # -- placeholder allocation --------------------------------------------------
    def placeholder_for(self, label: str, value: str) -> str:
        norm = self._norm(label, value)
        key = (label, norm)
        if key in self.key2ph:
            return self.key2ph[key]
        if label == "PERSON":
            alias = self._person_alias(norm)
            if alias:
                self.key2ph[key] = alias
                return alias
        self.counters[label] += 1
        ph = f"<{label}_{self.counters[label]}>"
        self.key2ph[key] = ph
        self.ph2val[ph] = value
        self.ph2label[ph] = label
        return ph

    def redact(self, label: str, value: str) -> str:
        self.redacted.append((label, value))
        return f"[REDACTED_{label}]"

    def fpe_token(self, label: str, value: str) -> str:
        norm = self._norm(label, value)
        if (label, norm) in self.key2ph:
            return self.key2ph[(label, norm)]
        n = 0
        while True:
            stream = hashlib.sha256(hmac.new(self._key, f"{label}|{norm}|{n}".encode(), "sha256").digest()).digest()
            it = iter(stream * 4)
            fake = "".join(
                str(next(it) % 10) if ch.isdigit() else
                chr(65 + next(it) % 26) if ch.isupper() else
                chr(97 + next(it) % 26) if ch.islower() else ch for ch in value)
            if fake != value and fake not in self.fpe:
                break
            n += 1
        self.fpe[fake] = value
        self.key2ph[(label, norm)] = fake
        self.ph2val[fake] = value
        self.ph2label[fake] = label
        return fake

    # -- helpers -----------------------------------------------------------------
    def token_spans(self, text: str):
        spans = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
        for fake in self.fpe:
            spans += [(m.start(), m.end()) for m in re.finditer(re.escape(fake), text)]
        return spans

    def originals(self) -> List[Tuple[str, str]]:
        return [(self.ph2label[p], v) for p, v in self.ph2val.items()] + list(self.redacted)

    def residual_entities(self, text: str) -> List[Entity]:
        """Defence in depth: any original value (or a >=3 char name token) still present in the text."""
        spans, found = self.token_spans(text), []
        for label, value in self.originals():
            pats = [re.escape(value)]
            if label == "PERSON":
                pats += [rf"\b{re.escape(t)}\b" for t in re.findall(r"[A-Za-z]{3,}", value)]
            for p in pats:
                for m in re.finditer(p, text, re.I):
                    if not any(m.start() < e and m.end() > s for s, e in spans):
                        found.append(Entity(label, m.start(), m.end(), 1.0, m.group(), "residual", pass_no=2))
        found.sort(key=lambda e: (-(e.end - e.start), e.start))
        out: List[Entity] = []
        for e in found:
            if all(e.end <= o.start or e.start >= o.end for o in out):
                out.append(e)
        return out

    def leaks_in(self, text: str) -> List[Tuple[str, str]]:
        """Final gate: normalised search of every original value inside the exact outbound bytes."""
        hay, leaks = _alnum(text), []
        for label, value in self.originals():
            n = _alnum(value)
            if len(n) >= 4 and n in hay:
                leaks.append((label, value))
            elif label == "PERSON":
                for tok in re.findall(r"[A-Za-z]{4,}", value):
                    if re.search(rf"\b{re.escape(tok)}\b", text, re.I):
                        leaks.append((label, tok))
        return leaks

    def wipe(self):
        self.key2ph.clear(); self.ph2val.clear(); self.ph2label.clear(); self.fpe.clear(); self.redacted.clear()


def apply_masks(text: str, ents: List[Entity], policy, vault: Vault) -> str:
    out, pos = [], 0
    for e in sorted(ents, key=lambda x: x.start):
        if e.start < pos:
            continue
        act = policy.action(e.label)
        value = text[e.start:e.end]
        if e.forced_placeholder:
            ph = e.forced_placeholder
        elif act == "redact" or act == "block":
            ph = vault.redact(e.label, value)
        elif act == "fpe":
            ph = vault.fpe_token(e.label, value)
        else:
            ph = vault.placeholder_for(e.label, value)
        e.placeholder, e.action = ph, act
        out.append(text[pos:e.start]); out.append(ph)
        pos = e.end
    out.append(text[pos:])
    return "".join(out)
