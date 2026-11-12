"""Rule-based name + address finders tuned for Indian English and code-mixed (Hinglish / Kanglish) text.

They run as additional Presidio recognizers next to the statistical NER model (spaCy / GLiNER) and
double as the offline fallback when no model is installed.
Each finder returns a list of (label, start, end, score).
"""
import re
from typing import List, Tuple

Span = Tuple[str, int, int, float]

FIRST = {"Rahul", "Priya", "Amit", "Suresh", "Anjali", "Ramesh", "Lakshmi", "Manjunath", "Vijay", "Sunita",
         "Deepak", "Kavita", "Arun", "Meena", "Sanjay", "Pooja", "Ravi", "Anita", "Mahesh", "Geeta", "Ajay",
         "Neha", "Kiran", "Rajesh", "Sneha"}
SURN = {"Sharma", "Patel", "Gowda", "Kumar", "Singh", "Reddy", "Nair", "Iyer", "Verma", "Gupta", "Joshi",
        "Hegde", "Patil", "Shetty", "Rao", "Das", "Mehta", "Yadav"}

STOP = {w.lower() for w in """The This That My Your Our Aadhaar Aadhar Pan Address Phone Mobile Email Date Age Loan Policy
Claim Ticket Dear Sir Madam Hi Hello Namaste Regards Thanks Thank Please Kindly Name Contact Customer Applicant Account
Bank Branch Amount Rs INR Hai Hain Ka Ki Ke Ko Ne Se Aur Mera Meri Naam Nanna Hesaru Is Was And For With From Passport
Voter GSTIN GST ID No Number Mr Mrs Ms Dr Shri Smt Sri Born Occupation Employer Company Income Salary Insurance Hospital
Claimant Nominee Policyholder Borrower Subject Re KYC DOB Gender Male Female Verified By Manager Declaration Signature
Place Application Form Record Proprietor Director Owner Guarantor Father Mother Spouse Full Permanent Current Residential
Later Then Also After Before Today Yesterday Tomorrow Hence However Thus Finally Meanwhile Call Reach Send Check See Refer Attn Kindly
UTR Incident Relation Limited Ltd Pvt Private Urgent Issue Problem Update Status Help Need Unable Not
Summarize Summary Explain Tell Analyze Analyse Write Extract Describe Provide Find What Who Why How""".split()}
STOP.update(w.lower() for w in """मेरा मेरी नाम है ग्राहक ग्राहकों सहायता और का की के को ने से फोन मोबाइल
ನನ್ನ ನನ್ನದು ಹೆಸರು ಗ್ರಾಹಕ ಗ್ರಾಹಕರ ಬೆಂಬಲ ಮತ್ತು ಅವರ ಅವರು ಇದೆ ಇದ್ದಾರೆ ಗೆ ನಿಂದ ಸಂಪರ್ಕ ಕರೆ ಮೊಬೈಲ್ ಫೋನ್""".split())
STOP.update(w.lower() for w in """Case Dossier Support Financial Profile Report Reference Master Core Privacy Gateway
Demo Test Synthetic Data Person Persons Names Placeholder Consistency Processing Prompt Target Karnataka Holder Sole
Signatory Verification Details Web Portal Client Repeated Sections""".split())

_TOK = r"(?:[A-Z][a-z]{1,20}|[A-Z]{2,20}|[A-Z]\.|[\u0900-\u097F]+|[\u0C80-\u0CFF]+)"
_NAME = rf"({_TOK}(?:(?:[ \t]+|\n){_TOK}){{0,3}})"
_STRONG = (r"(?:my\s+name\s+is|name\s+is|name\s*[:=\-–]|full(?:\s+legal)?\s+name|applicant(?:'s)?(?:\s+name)?|co-?applicant|"
           r"customer(?:'s)?[ \t]+name|customer(?=[ \t]*[:=])|claimant(?:\s*\([^)\n]{0,30}\))?|"
           r"policy\s*holder|borrower|nominee|beneficiary|"
           r"account\s+holder|proprietor|director|owner|guarantor|authori[sz]ed\s+signatory|father'?s?\s+name|"
           r"mother'?s?\s+name|spouse(?:'s)?\s+name|contact\s+person|mera\s+naam|mera\s+name|meri\s+naam|naam|"
           r"nanna\s+hesaru|hesaru|मेरा\s+नाम(?:\s+है)?|ग्राहक(?:\s+का)?\s+नाम|नाम|"
           r"ನನ್ನ\s+ಹೆಸರು|ಗ್ರಾಹಕರ\s+ಹೆಸರು|ಹೆಸರು|s/o|d/o|w/o|c/o|mr\.?|mrs\.?|ms\.?|shri|smt\.?|sri|dr\.?|prof\.?)")
_WEAK = r"(?:i\s+am|i\s*,|dear|regards,?|thanks,?|sincerely,?|yours\s+truly,?|verified\s+by|branch\s+manager)"

STRONG_RE = re.compile(rf"\b(?i:{_STRONG})[ \t]*[:=\-–]?\s*{_NAME}")
WEAK_RE = re.compile(rf"\b(?i:{_WEAK})[ \t]*[:=\-–]?\s*{_NAME}")
SUFFIX_RE = re.compile(rf"\b({_TOK}(?:[ \t]+{_TOK})?)[ \t]+(?i:ji|bhai|sahab|saheb|garu|avare)\b")
GAZ_RE = re.compile(r"\b[A-Z][a-z]{1,20}(?:(?:[ \t]+|\n)[A-Z][a-z]{1,20}){0,3}")


def _trim(text: str, start: int, end: int):
    """Drop leading stop-words and cut at the first stop-word after the name started."""
    toks = [(m.group(), m.start() + start, m.end() + start) for m in re.finditer(r"\S+", text[start:end])]
    kept, started = [], False
    for tok, s, e in toks:
        is_stop = tok.strip(".,:;!?।,").lower() in STOP
        if not started and is_stop:
            continue
        if started and is_stop:
            break
        started = True
        kept.append((tok, s, e))
    if not kept:
        return None
    words = [t for t, _, _ in kept if not re.fullmatch(r"[A-Z]\.", t)]
    if not words:
        return None
    return kept[0][1], kept[-1][2], words


def find_names(text: str) -> List[Span]:
    out: List[Span] = []
    for rx, score, weak in ((STRONG_RE, 0.85, False), (WEAK_RE, 0.7, True)):
        for m in rx.finditer(text):
            r = _trim(text, m.start(1), m.end(1))
            if not r:
                continue
            s, e, words = r
            if weak and len(words) < 2 and not (words[0] in FIRST or words[0] in SURN):
                continue
            out.append(("PERSON", s, e, score))
    for m in SUFFIX_RE.finditer(text):
        r = _trim(text, m.start(1), m.end(1))
        if r:
            out.append(("PERSON", r[0], r[1], 0.75))
    for m in GAZ_RE.finditer(text):
        if not any(t in FIRST or t in SURN for t in m.group().split()):
            continue
        r = _trim(text, m.start(), m.end())
        if r:
            out.append(("PERSON", r[0], r[1], 0.6))
    return out


PIN = r"\b[1-9]\d{2}\s?\d{3}\b"
_CUE = (r"(?:permanent\s+address|communication\s+address|residential\s+address|current\s+address|"
        r"correspondence\s+address|address|addr|residing\s+at|resident\s+of|r/o|lives\s+at|staying\s+at|"
        r"located\s+at|ವಿಳಾಸ|पता)")
ADDR_PIN_CUE = re.compile(rf"\b(?i:{_CUE})[ \t]*(?:is|:|-|–)?[ \t]*([^\n]{{8,200}}?{PIN})")
ADDR_EOL_CUE = re.compile(rf"\b(?i:{_CUE})[ \t]*(?:is|:|-|–)?[ \t]*([^\n]{{8,160}}?)(?=\.\s+[A-Z]|\s*\n|\s*$)")
_W = r"[\w./#'-]+"
ADDR_CHAIN = re.compile(rf"((?:{_W}(?:[ \t]+{_W}){{0,4}},[ \t]*){{2,6}}{_W}(?:[ \t]+{_W}){{0,3}}[ ,\-–]*{PIN})")


def find_addresses(text: str) -> List[Span]:
    out: List[Span] = []
    for rx, score in ((ADDR_PIN_CUE, 0.9), (ADDR_EOL_CUE, 0.75), (ADDR_CHAIN, 0.6)):
        for m in rx.finditer(text):
            if rx is ADDR_EOL_CUE:
                prefix = text[max(0, m.start(1) - 40):m.start(1)]
                value = m.group(1)
                if not re.search(r"\d|[,#]", value) and not re.search(r"[:=]\s*$", prefix):
                    continue
            out.append(("ADDRESS", m.start(1), m.end(1), score))
    return out
