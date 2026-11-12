"""Stage 4 - Reinsert: restore original values locally, safely.

Safety properties (all unit-tested)
  * exact (label, number) lookup - NO fuzzy matching, so one person's data can never replace another's
  * tolerant parsing of how LLMs rewrite placeholders: <PERSON_1>, < person_1 >, [PERSON_1], PERSON_1, PERSON\\_1 ...
  * `PERSON_1` never matches inside `PERSON_10` (digits are captured greedily)
  * unknown / hallucinated placeholders (<PERSON_9>) are left untouched and reported, never guessed
  * dropped placeholders are simply absent from the output and reported
  * JSON answers are restored value-by-value so quotes in addresses cannot break the JSON
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List

from .masking import Vault
from .recognizers import ALL_LABELS

_LBL = "|".join(sorted(ALL_LABELS, key=len, reverse=True))
PH_RE = re.compile(rf"[<\[{{(]\s*({_LBL})\s*\\?_\s*(\d+)\s*[>\]}})]|(?<![\w<\[])({_LBL})\\?_(\d+)(?!\w)", re.I)


@dataclass
class ReinsertResult:
    text: str
    restored: List[str] = field(default_factory=list)     # canonical placeholders that were restored
    unresolved: List[str] = field(default_factory=list)   # placeholders the LLM produced that we never issued
    dropped: List[str] = field(default_factory=list)      # issued placeholders absent from the response


def _restore_text(text: str, vault: Vault, restored: list, unresolved: list) -> str:
    def sub(m):
        label = (m.group(1) or m.group(3)).upper()
        canon = f"<{label}_{int(m.group(2) or m.group(4))}>"
        val = vault.ph2val.get(canon)
        if val is None or vault.ph2label.get(canon) != label:
            unresolved.append(canon)
            return m.group(0)
        restored.append(canon)
        return val
    text = PH_RE.sub(sub, text)
    for fake in sorted(vault.fpe, key=len, reverse=True):         # format-preserving tokens: exact string match
        if fake in text:
            text = text.replace(fake, vault.fpe[fake])
            restored.append(fake)
    return text


def _walk(node, fn):
    if isinstance(node, str):
        return fn(node)
    if isinstance(node, list):
        return [_walk(x, fn) for x in node]
    if isinstance(node, dict):
        return {k: _walk(v, fn) for k, v in node.items()}
    return node


def reinsert(llm_text: str, vault: Vault) -> ReinsertResult:
    restored, unresolved = [], []
    out = None
    stripped = llm_text.strip()
    body = re.sub(r"^```(?:json)?\s*|\s*```$", "", stripped)
    if body[:1] in "{[":
        try:
            data = json.loads(body)
            out = json.dumps(_walk(data, lambda s: _restore_text(s, vault, restored, unresolved)),
                             ensure_ascii=False, indent=2)
        except ValueError:
            out = None
    if out is None:
        out = _restore_text(llm_text, vault, restored, unresolved)
    issued = [p for p in vault.ph2val if p not in vault.fpe]
    dropped = [p for p in issued if p not in restored]
    return ReinsertResult(out, sorted(set(restored)), sorted(set(unresolved)), dropped)
