"""India-specific identifier recognizers.

One declarative spec list drives BOTH engines:
  * Presidio: every spec becomes a `PatternRecognizer` (see detector.build_presidio_recognizers)
  * Built-in fallback engine: same regexes/validators, used only if Presidio is not installed
"""
import re
import ipaddress
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


_BANK_ACCOUNT_CONTEXT = re.compile(
    r"\b(?:bank\s+account|account\s+(?:number|no\.?)|a/c\s*(?:number|no\.?)?|iban)\b", re.I
)
_ACCOUNT_NUMBER = re.compile(r"(?<!\d)\d{9,18}(?!\d)")
_IP_CANDIDATE = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!(?:\.\d)|\w)|"
    r"(?<![\w:])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{0,4}(?![\w:])",
    re.I,
)


def find_bank_accounts(text: str):
    out = []
    for match in _ACCOUNT_NUMBER.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        prefix = text[max(line_start, match.start() - 100):match.start()]
        if _BANK_ACCOUNT_CONTEXT.search(prefix):
            out.append(("BANK_ACCOUNT", match.start(), match.end(), 0.9))
    return out


def find_ip_addresses(text: str):
    out = []
    for match in _IP_CANDIDATE.finditer(text):
        try:
            ipaddress.ip_address(match.group())
        except ValueError:
            continue
        out.append(("IP_ADDRESS", match.start(), match.end(), 0.95))
    return out


PAN_HOLDER_TYPES = set("PCHFATBLJG")


def _pan_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    return len(s) == 10 and s[3] in PAN_HOLDER_TYPES


def _aadhaar_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return len(d) == 12 and d[0] in "23456789" and verhoeff_valid(d)


def _luhn_ok(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        value = int(digit)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


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
    IdSpec("IN_IFSC", "BANK_ACCOUNT",
           [("ifsc", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.9)],
           ["ifsc", "ifsc code", "bank"], None),
    IdSpec("CREDIT_CARD", "CREDIT_CARD",
           [("credit_card", r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", 0.45)],
           ["credit card", "debit card", "card number", "card no", "visa", "mastercard"], _luhn_ok),
    IdSpec("DATE_TIME", "DATE_OF_BIRTH",
           [("birth_date_numeric", r"\b(?:0?[1-9]|[12]\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/](?:19|20)\d{2}\b", 0.35),
            ("birth_date_iso", r"\b(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])\b", 0.35),
            ("birth_date_month", r"\b(?:0?[1-9]|[12]\d|3[01])\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:19|20)\d{2}\b", 0.35)],
           ["dob", "d.o.b", "date of birth", "born", "birth date"], None),
]

ENTITY_TO_LABEL = {s.entity: s.label for s in SPECS}
ENTITY_TO_LABEL.update({
    "PERSON": "PERSON", "ADDRESS": "ADDRESS", "BANK_ACCOUNT": "BANK_ACCOUNT", "IP_ADDRESS": "IP_ADDRESS",
})
ENTITY_TO_LABEL.update({s.label: s.label for s in SPECS})
LABEL_CONTEXT = {s.label: s.context for s in SPECS}
ALL_LABELS = ["PERSON", "ADDRESS", "AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT", "PHONE", "EMAIL",
              "CREDIT_CARD", "BANK_ACCOUNT", "IP_ADDRESS", "DATE_OF_BIRTH"]

# Words that, just before a number/code, say it is NOT an identity number (txn ids, policy numbers ...)
NEGATIVE_CONTEXT = ["account", "a/c", "acct", "ref", "txn", "transaction", "utr", "order", "invoice",
                    "policy", "claim", "ticket", "case no", "serial", "cheque", "chq", "application no"]
