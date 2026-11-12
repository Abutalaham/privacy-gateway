import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("ANTHROPIC_API_KEY", None)

from gateway.audit import AuditLog  # noqa: E402
from gateway.checksums import gstin_valid, verhoeff_check_digit, verhoeff_valid  # noqa: E402
from gateway.detector import Detector  # noqa: E402
from gateway.llm import LLMRouter, MockBackend  # noqa: E402
from gateway.masking import Vault  # noqa: E402
from gateway.pipeline import LeakDetected, PolicyBlocked, PrivacyGateway, build_default_gateway  # noqa: E402
from gateway.reinsert import reinsert  # noqa: E402

DET = Detector()
PS_EXAMPLE = "My name is Rahul Sharma. My Aadhaar number is 1234-5678-9012 and my PAN is ABCDE1234F."


def gw(provider="mock", fallback="none", mode="faithful"):
    return build_default_gateway(provider, fallback, mode, os.path.join(tempfile.mkdtemp(), "a.db"), DET)


class Detection(unittest.TestCase):
    def test_problem_statement_example(self):
        r = gw().process(PS_EXAMPLE)
        self.assertEqual(r.sanitized_text,
                         "My name is <PERSON_1>. My Aadhaar number is <AADHAAR_1> and my PAN is <PAN_1>.")

    def test_checksums(self):
        self.assertTrue(gstin_valid("27AAPFU0939F1ZV"))
        self.assertTrue(verhoeff_valid("2363"))
        self.assertEqual(verhoeff_check_digit("236"), "3")

    def test_all_id_types(self):
        t = ("GSTIN 27AAPFU0939F1ZV, Voter ID ABC1234567, Passport No. K8369854, "
             "passport X4930323, mobile 98450 12345, email a.b@x.in")
        labels = {e.label for e in DET.detect(t)}
        self.assertTrue({"GSTIN", "VOTER_ID", "PASSPORT", "PHONE", "EMAIL"} <= labels)

    def test_txn_and_policy_numbers_are_not_ids(self):
        labels = [e.label for e in DET.detect("Bank UTR: 368362204552\nPolicy No: POL1234567")]
        self.assertNotIn("AADHAAR", labels)
        self.assertNotIn("VOTER_ID", labels)

    def test_code_mixed_names(self):
        t = "Namaste, mera naam Suresh Gowda hai. Nanna hesaru Chaitra Hegde. Priya ji ne bola."
        names = [e.text for e in DET.detect(t) if e.label == "PERSON"]
        self.assertIn("Suresh Gowda", names)
        self.assertIn("Chaitra Hegde", names)

    def test_address_with_pin(self):
        t = "Address: No. 12, 4th Cross, Jayanagar, Bengaluru - 560011 and then more text."
        self.assertTrue(any(e.label == "ADDRESS" and e.text.endswith("560011") for e in DET.detect(t)))

    def test_credit_card_bank_account_ip_and_dob(self):
        text = ("Card number: 4111 1111 1111 1111. Bank account no: 123456789012. IFSC: SBIN0001234. "
                "IP address: 203.0.113.8. DOB: 01/02/1990.")
        entities = DET.detect(text)
        labels = {entity.label for entity in entities}
        self.assertTrue({"CREDIT_CARD", "BANK_ACCOUNT", "IP_ADDRESS", "DATE_OF_BIRTH"} <= labels)
        self.assertIn("IFSC", labels)
        self.assertNotIn("BANK_ACCOUNT", [
            entity.label for entity in entities if entity.text == "SBIN0001234"
        ])

    def test_document_headings_and_report_dates_are_not_pii(self):
        text = (
            "RETAIL BANKING & CARD OPERATIONS — CUSTOMER CASE DOSSIER\n"
            "Customer Support & Financial Profile Report\n"
            "Report Date: 12 November 2026\n"
            "2.1 Narrative KYC & Address Verification Summary\n"
            "CUSTOMER SUPPORT PROCESSING PROMPT\n"
            "Date of Birth: 14 February 2002\n"
            "Customer: Aarav Mehta\n"
        )
        entities = DET.detect(text)
        names = [entity.text for entity in entities if entity.label == "PERSON"]
        dates = [entity.text for entity in entities if entity.label == "DATE_OF_BIRTH"]
        addresses = [entity.text for entity in entities if entity.label == "ADDRESS"]
        self.assertNotIn("CASE DOSSIER", names)
        self.assertNotIn("Support", names)
        self.assertNotIn("Profile Report", names)
        self.assertIn("Aarav Mehta", names)
        self.assertEqual(dates, ["14 February 2002"])
        self.assertEqual(addresses, [])


class Masking(unittest.TestCase):
    def test_consistent_placeholders(self):
        s = gw().process("Name: Rahul Sharma. Later Rahul Sharma called. PAN ABCDE1234F, again ABCDE1234F.").sanitized_text
        self.assertEqual(s.count("<PERSON_1>"), 2)
        self.assertEqual(s.count("<PAN_1>"), 2)
        self.assertNotIn("Rahul", s)

    def test_two_people_never_share_placeholder(self):
        s = gw().process("Applicant: Rahul Sharma. Nominee: Priya Sharma. Mr. Sharma signed.").sanitized_text
        self.assertIn("<PERSON_1>", s)
        self.assertIn("<PERSON_2>", s)
        self.assertNotIn("Sharma", s)                          # ambiguous surname is masked with its OWN placeholder

    def test_no_raw_pii_in_outbound(self):
        r = gw().process(PS_EXAMPLE + "\nAddress: No. 12, 4th Cross, Jayanagar, Mysuru - 570001")
        for raw in ("Rahul", "Sharma", "1234-5678-9012", "ABCDE1234F", "Jayanagar", "570001"):
            self.assertNotIn(raw, r.outbound_payload)


class Reinsertion(unittest.TestCase):
    def vault(self, n=10):
        v = Vault()
        for i in range(n):
            v.placeholder_for("PERSON", f"Person Number{i}")
        return v

    def test_prefix_safety(self):
        out = reinsert("<PERSON_1> and <PERSON_10>", self.vault()).text
        self.assertEqual(out, "Person Number0 and Person Number9")

    def test_llm_rewrites_format(self):
        out = reinsert("[PERSON_1], PERSON_2, <person_3>, < PERSON_4 >, PERSON\\_5, <PERSON_6>'s file", self.vault()).text
        self.assertEqual(out, "Person Number0, Person Number1, Person Number2, Person Number3, Person Number4, Person Number5's file")

    def test_hallucinated_placeholder_untouched(self):
        r = reinsert("<PERSON_99> and <AADHAAR_1>", self.vault(2))
        self.assertEqual(r.text, "<PERSON_99> and <AADHAAR_1>")
        self.assertEqual(sorted(r.unresolved), ["<AADHAAR_1>", "<PERSON_99>"])

    def test_plain_english_person_1_not_replaced(self):
        self.assertEqual(reinsert("Person 1 and person 2", self.vault(3)).text, "Person 1 and person 2")

    def test_dropped_reported(self):
        r = reinsert("only <PERSON_1> here", self.vault(3))
        self.assertEqual(r.dropped, ["<PERSON_2>", "<PERSON_3>"])

    def test_json_safe(self):
        v = Vault(); v.placeholder_for("ADDRESS", 'Flat 4 "Sai" Apts, Pune - 411001')
        import json
        self.assertEqual(json.loads(reinsert('{"addr": "<ADDRESS_1>"}', v).text)["addr"], 'Flat 4 "Sai" Apts, Pune - 411001')

    def test_end_to_end_all_llm_behaviours(self):
        g = gw(mode="rotate")
        for _ in range(10):
            r = g.process(PS_EXAMPLE)
            for ph in g.router.backends[0].last_emitted:
                self.assertIn(r.mapping[ph], r.final_response)


class Safety(unittest.TestCase):
    def test_instruction_pii_is_masked_before_sending(self):
        r = gw().process(PS_EXAMPLE, instructions="Summarize Rahul Sharma and rahul.private@example.com.")
        self.assertNotIn("Rahul Sharma", r.outbound_payload)
        self.assertNotIn("rahul.private@example.com", r.outbound_payload)
        self.assertIn("<PERSON_1>", r.outbound_payload)
        self.assertIn("<EMAIL_1>", r.outbound_payload)

    def test_final_leak_gate_blocks_tampered_provider_payload(self):
        g = gw()
        backend = g.router.backends[0]
        original_build = backend.build_request

        def inject_original(*args, **kwargs):
            request = original_build(*args, **kwargs)
            request.body += b" Rahul Sharma"
            return request

        with patch.object(backend, "build_request", side_effect=inject_original):
            with self.assertRaises(LeakDetected):
                g.process(PS_EXAMPLE)
        self.assertEqual(g.audit.recent(1)[0]["status"], "BLOCKED_LEAK")

    def test_marketing_blocks_aadhaar(self):
        g = gw()
        with self.assertRaises(PolicyBlocked) as cm:
            g.process(PS_EXAMPLE, purpose="marketing")
        self.assertIn("AADHAAR", cm.exception.labels)
        self.assertEqual(g.audit.recent(1)[0]["outbound_payload"], "(nothing sent)")

    def test_format_preserving_roundtrip(self):
        r = gw().process(PS_EXAMPLE, purpose="analytics_fpe")
        self.assertNotIn("ABCDE1234F", r.sanitized_text)
        self.assertRegex(r.sanitized_text, r"\b[A-Z]{5}\d{4}[A-Z]\b")
        self.assertIn("ABCDE1234F", r.final_response)

    def test_fallback_to_local_slm_when_external_down(self):
        r = gw(provider="anthropic", fallback="local").process(PS_EXAMPLE)   # no API key -> primary fails
        self.assertTrue(r.fallback_used)
        self.assertEqual(r.provider, "local-extractive")
        self.assertIn("Rahul Sharma", r.final_response)

    def test_audit_record_and_chain(self):
        g = gw()
        r = g.process(PS_EXAMPLE, doc_type="kyc")
        rec = g.audit.get(r.request_id)
        self.assertEqual(rec["outbound_payload"], r.outbound_payload)
        self.assertIn("mock-llm-1", rec["model"])
        self.assertNotIn("1234-5678-9012", str(rec))
        self.assertTrue(g.audit.verify_chain())
        import sqlite3
        with sqlite3.connect(g.audit.path) as c:
            c.execute("UPDATE audit_log SET outbound_payload='tampered'")
        self.assertFalse(g.audit.verify_chain())


if __name__ == "__main__":
    unittest.main(verbosity=2)
