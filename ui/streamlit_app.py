"""Demo UI (PS 3.6).  Run:  streamlit run ui/streamlit_app.py
A = original input | B = exact outbound payload + detected entities | C = final response after local reinsertion"""
import html
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st  # noqa: E402

from data.generate_dataset import main as generate  # noqa: E402
from gateway.detector import Detector  # noqa: E402
from gateway.llm import AllBackendsFailed  # noqa: E402
from gateway.pipeline import LeakDetected, PolicyBlocked, build_default_gateway  # noqa: E402
from gateway.policy import POLICIES  # noqa: E402

st.set_page_config(page_title="DPDP Privacy Gateway", layout="wide")
COLORS = {"PERSON": "#fde68a", "ADDRESS": "#bfdbfe", "AADHAAR": "#fecaca", "PAN": "#fbcfe8", "GSTIN": "#ddd6fe",
          "VOTER_ID": "#a7f3d0", "PASSPORT": "#fed7aa", "PHONE": "#e5e7eb", "EMAIL": "#cffafe"}


@st.cache_resource
def detector():
    return Detector()


def mark(text, spans):          # spans: [(start, end, label)]
    out, pos = [], 0
    for s, e, lab in sorted(spans):
        out.append(html.escape(text[pos:s]))
        out.append(f'<mark style="background:{COLORS.get(lab, "#eee")};padding:0 2px;border-radius:3px" title="{lab}">{html.escape(text[s:e])}</mark>')
        pos = e
    out.append(html.escape(text[pos:]))
    return '<div style="white-space:pre-wrap;font-family:monospace;font-size:13px">' + "".join(out) + "</div>"


def mark_placeholders(text):
    spans = [(m.start(), m.end(), re.sub(r"[<>\[\]]|_\d+", "", m.group())) for m in re.finditer(r"<[A-Z_]+_\d+>|\[REDACTED_[A-Z_]+\]", text)]
    return mark(text, [(s, e, l.replace("REDACTED_", "")) for s, e, l in spans])


if not os.path.exists("data/synthetic_docs.json"):
    generate("data/synthetic_docs.json")
docs = json.load(open("data/synthetic_docs.json", encoding="utf-8"))

with st.sidebar:
    st.header("Gateway settings")
    provider = st.selectbox("External LLM backend", ["mock", "anthropic", "openai", "ollama"],
                            help="anthropic/openai need ANTHROPIC_API_KEY / OPENAI_API_KEY. Missing key or outage => automatic local SLM fallback.")
    mock_mode = st.selectbox("Mock LLM behaviour", ["rotate", "faithful", "reorder", "paraphrase", "drop", "hallucinate"],
                             disabled=provider != "mock")
    fallback = st.selectbox("Fallback when external LLM fails", ["local", "ollama", "none"])
    purpose = st.selectbox("Processing purpose (policy)", list(POLICIES))
    st.caption(POLICIES[purpose].description)
    task = st.radio("Task", ["summarize", "extract"], horizontal=True)
    st.caption(f"Detection engine: **{detector().engine}**")

st.title("DPDP-Ready Privacy Gateway for Enterprise LLMs")
pick = st.selectbox("Sample document", ["(write your own)"] + [f"{d['id']} - {d['doc_type']}" for d in docs])
default = docs[int(pick.split()[0][3:]) - 1]["text"] if pick != "(write your own)" else \
    "My name is Rahul Sharma. My Aadhaar number is 1234-5678-9012 and my PAN is ABCDE1234F."
text = st.text_area("Document", default, height=170)

if st.button("Run through gateway", type="primary"):
    gw = build_default_gateway(provider, fallback, mock_mode, detector=detector())
    try:
        r = gw.process(text, task=task, purpose=purpose, doc_type=None if pick.startswith("(") else pick.split(" - ")[-1])
    except PolicyBlocked as exc:
        st.error(f"Blocked by purpose policy '{purpose}': {', '.join(exc.labels)} may not be processed. Nothing left the organisation.")
        st.stop()
    except LeakDetected as exc:
        st.error(f"Request blocked by the final leak gate ({len(exc.leaks)} raw value(s)). Nothing was sent.")
        st.stop()
    except AllBackendsFailed as exc:
        st.error(f"No LLM backend available: {exc}")
        st.stop()

    a, b, c = st.columns(3)
    with a:
        st.subheader("A. Original input")
        st.markdown(mark(r.original_text, [(e["start"], e["end"], e["label"]) for e in r.entities if e["pass"] == 1]), unsafe_allow_html=True)
    with b:
        st.subheader("B. Outbound sanitized payload")
        st.caption(f"Sent to: **{r.provider}** / `{r.model}`" + ("  (fallback used)" if r.fallback_used else ""))
        st.markdown(mark_placeholders(r.sanitized_text), unsafe_allow_html=True)
        rows = [{"type": e["label"], "placeholder": e["placeholder"], "action": e["action"], "confidence": e["score"]} for e in r.entities]
        st.dataframe(rows, hide_index=True, use_container_width=True)
    with c:
        st.subheader("C. Final response (after local reinsertion)")
        st.markdown(f'<div style="white-space:pre-wrap">{html.escape(r.final_response)}</div>', unsafe_allow_html=True)
        ri = r.reinsertion
        st.caption(f"restored {len(ri['restored'])} | dropped by LLM {len(ri['dropped'])} | unknown placeholders left untouched {len(ri['unresolved'])}")

    leaked = [v for v in r.mapping.values() if len(re.sub(r'\W', '', v)) >= 4 and v in r.outbound_payload]
    (st.success if not leaked else st.error)(
        f"Leak check on the exact outbound bytes: {len(leaked)} raw PII values found ({r.leak_check['values_checked']} values checked)  |  "
        f"SHA-256 {r.leak_check['outbound_sha256'][:16]}...  |  gateway overhead {r.timings['gateway_overhead_ms']:.1f} ms")
    with st.expander("Exact request body sent to the external model (what the audit log stores)"):
        st.code(r.outbound_payload, language="json")
    with st.expander("Attempts (shows automatic fallback)"):
        st.json([{k: v for k, v in a_.items() if k != "payload"} for a_ in r.attempts])

tab1, tab2 = st.tabs(["Audit log", "Metrics report"])
with tab1:
    gw0 = build_default_gateway("mock", "none", detector=detector())
    st.caption(f"Hash chain intact: {gw0.audit.verify_chain()}")
    st.dataframe([{k: v for k, v in rec.items() if k in ("request_id", "created_at", "purpose", "status", "provider", "model", "entity_types", "outbound_sha256")}
                  for rec in gw0.audit.recent(30)], use_container_width=True)
with tab2:
    if os.path.exists("reports/metrics.md"):
        st.markdown(open("reports/metrics.md").read())
    else:
        st.info("Run `python -m eval.evaluate` to generate the report.")
