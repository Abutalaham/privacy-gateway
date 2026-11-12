"""Purpose-based privacy policies (Additional Feature 1).

Actions per entity label:
  mask   -> typed placeholder <PERSON_1>, reversible locally
  fpe    -> format-preserving token (same shape as original), reversible locally
  redact -> [REDACTED_X], irreversible (no mapping kept)
  block  -> request is rejected, nothing leaves the organisation
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict

from .recognizers import ALL_LABELS


@dataclass
class Policy:
    name: str
    description: str
    actions: Dict[str, str] = field(default_factory=dict)
    default_action: str = "mask"

    def action(self, label: str) -> str:
        return self.actions.get(label, self.default_action)


POLICIES: Dict[str, Policy] = {
    "default": Policy("default", "Mask every detected PII value with a reversible typed placeholder."),
    "kyc_verification": Policy("kyc_verification", "KYC review: mask everything, reversible."),
    "customer_support": Policy("customer_support", "Support tickets: mask everything, reversible."),
    "loan_underwriting": Policy("loan_underwriting", "Loan underwriting: mask everything, reversible."),
    "analytics_fpe": Policy("analytics_fpe",
                            "Downstream validators need field shapes: identity numbers become format-preserving tokens.",
                            {l: "fpe" for l in ("AADHAAR", "PAN", "GSTIN", "PASSPORT", "VOTER_ID", "PHONE")}),
    "marketing": Policy("marketing",
                        "Marketing must never see government IDs: Aadhaar/PAN/Passport/Voter ID are BLOCKED, "
                        "other contact data is irreversibly redacted.",
                        {"AADHAAR": "block", "PAN": "block", "PASSPORT": "block", "VOTER_ID": "block",
                         "GSTIN": "redact", "PHONE": "redact", "EMAIL": "redact", "ADDRESS": "redact",
                         "PERSON": "mask"}),
}


def get_policy(name: str) -> Policy:
    path = os.getenv("PG_POLICY_FILE")
    if path and os.path.exists(path):                        # optional JSON overrides: {"name": {"AADHAAR": "block"}}
        custom = json.load(open(path, encoding="utf-8"))
        if name in custom:
            return Policy(name, "custom policy", custom[name])
    if name not in POLICIES:
        raise KeyError(f"Unknown purpose/policy '{name}'. Available: {sorted(POLICIES)}")
    return POLICIES[name]
