"""India-specific identifier recognizers.

One declarative spec list drives BOTH engines:
  * Presidio: every spec becomes a `PatternRecognizer` (see detector.build_presidio_recognizers)
  * Built-in fallback engine: same regexes/validators, used only if Presidio is not installed
"""
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .checksums import gstin_valid, verhoeff_valid


@dataclass
class IdSpec:
    entity: str                       # Presidio entity name
    label: str                        # placeholder label used in <LABEL_n>
    patterns: List[Tuple[str, str, float]]   # (name, regex, base score)
    context: List[str]
    validator: Optional[Callable[[str], bool]] = None


PAN_HOLDER_TYPES = set("PCHFATBLJG")


def _pan_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    return len(s) == 10 and s[3] in PAN_HOLDER_TYPES


def _aadhaar_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return len(d) == 12 and d[0] in "23456789" and verhoeff_valid(d)


# NOTE: a failing checksum must NOT reject the match (validator False -> "unknown", not "invalid").
# The sample in the problem statement (1234-5678-9012) is not Verhoeff-valid but must still be masked.
SPECS: List[IdSpec] = [
    IdSpec("IN_AADHAAR", "AADHAAR",
           [("aadhaar_grouped", r"(?<![\d-])\d{4}[ -]\d{4}[ -]\d{4}(?![\d-])", 0.5),
            ("aadhaar_bare", r"(?<!\d)\d{12}(?!\d)", 0.3)],
           ["aadhaar", "aadhar", "adhaar", "uid", "uidai", "aadhaar number", "आधार"], _aadhaar_ok),
    IdSpec("IN_PAN", "PAN",
           [("pan", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0.6)],
           ["pan", "permanent account number", "income tax"], _pan_ok),
    IdSpec("IN_GSTIN", "GSTIN",
           [("gstin", r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", 0.75)],
           ["gstin", "gst", "gst no", "gst number"], gstin_valid),
    IdSpec("IN_VOTER", "VOTER_ID",
           [("voter_epic", r"\b[A-Z]{3}\d{7}\b", 0.4)],
           ["voter", "epic", "election", "electoral", "voter id"], None),
    IdSpec("IN_PASSPORT", "PASSPORT",
           [("passport", r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", 0.4),
            ("passport_loose", r"\b[A-Z][1-9]\d\s?\d{4}[1-9]\b", 0.3)],   # any letter, only accepted with context
           ["passport", "travel document"], None),
    IdSpec("IN_PHONE", "PHONE",
           [("in_mobile", r"(?<![\w-])(?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", 0.5)],
           ["phone", "mobile", "mob", "contact", "call", "whatsapp", "cell"], None),
    IdSpec("EMAIL_ADDRESS", "EMAIL",
           [("email", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 0.9)],
           ["email", "e-mail", "mail"], None),
]

ENTITY_TO_LABEL = {s.entity: s.label for s in SPECS}
ENTITY_TO_LABEL.update({"PERSON": "PERSON", "ADDRESS": "ADDRESS"})
LABEL_CONTEXT = {s.label: s.context for s in SPECS}
ALL_LABELS = ["PERSON", "ADDRESS", "AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT", "PHONE", "EMAIL"]

# Words that, just before a number/code, say it is NOT an identity number (txn ids, policy numbers ...)
NEGATIVE_CONTEXT = ["account", "a/c", "acct", "ref", "txn", "transaction", "utr", "order", "invoice",
                    "policy", "claim", "ticket", "case no", "serial", "cheque", "chq", "application no"]
