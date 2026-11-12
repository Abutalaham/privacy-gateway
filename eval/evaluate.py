"""Metrics report (PS section 3.8).  Run:  python -m eval.evaluate
Produces reports/metrics.json + reports/metrics.md
  * PII leakage count      - gold PII values found in the exact outbound bytes (target 0)
  * precision / recall     - per entity type, overlap-match (IoU>=0.5) and strict exact-span
  * reinsertion accuracy   - LLM output is deliberately paraphrased/reordered/dropped/hallucinated (MockBackend)
  * latency                - gateway overhead per request = total - time spent inside the LLM call
"""
import json
import os
import re
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.generate_dataset import main as generate  # noqa: E402
from gateway.detector import Detector  # noqa: E402
from gateway.pipeline import build_default_gateway  # noqa: E402
from gateway.recognizers import ALL_LABELS  # noqa: E402

DATA = "data/synthetic_docs.json"


def _alnum(s): return re.sub(r"[^0-9a-z]", "", s.lower())


def _iou(a, b):
    inter = max(0, min(a[1], b[1]) - max(a[0], b[0]))
    return inter / ((a[1] - a[0]) + (b[1] - b[0]) - inter) if inter else 0.0


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return round(p, 3), round(r, 3), round(2 * p * r / (p + r), 3) if p + r else 0.0


def match(preds, golds, strict):
    used, tp = set(), 0
    for g in golds:
        for i, p in enumerate(preds):
            ok = (p[0] == g[0]) and ((p[1], p[2]) == (g[1], g[2]) if strict else _iou((p[1], p[2]), (g[1], g[2])) >= 0.5)
            if i not in used and ok:
                used.add(i); tp += 1; break
    return tp, len(preds) - tp, len(golds) - tp


def run(report_dir="reports"):
    if not os.path.exists(DATA):
        generate(DATA)
    docs = json.load(open(DATA, encoding="utf-8"))
    db = os.path.join(tempfile.mkdtemp(), "eval_audit.db")
    gw = build_default_gateway(provider="mock", fallback="none", mock_mode="rotate", db_path=db, detector=Detector())
    mock = gw.router.backends[0]
    counts = {m: {l: [0, 0, 0] for l in ALL_LABELS} for m in ("overlap", "exact")}
    leaks, leak_by_type, checked_values = 0, {}, 0
    re_total = re_ok = cross = halluc_total = halluc_safe = drop_cases = drop_ok = 0
    overhead, llm_ms, e2e, by_mode = [], [], [], {}
    recheck_saves = 0

    for d in docs:
        res = gw.process(d["text"], task="summarize", purpose="default", doc_type=d["doc_type"])
        golds = [(e["type"], e["start"], e["end"]) for e in d["entities"]]
        pass1 = [(e["label"], e["start"], e["end"]) for e in res.entities if e["pass"] == 1]
        recheck_saves += sum(1 for e in res.entities if e["pass"] == 2)
        for mode, strict in (("overlap", False), ("exact", True)):
            for lab in ALL_LABELS:
                tp, fp, fn = match([p for p in pass1 if p[0] == lab], [g for g in golds if g[0] == lab], strict)
                c = counts[mode][lab]; c[0] += tp; c[1] += fp; c[2] += fn
        # ---- leakage: every GOLD value is searched in the exact outbound bytes ----
        hay = _alnum(res.outbound_payload)
        for e in d["entities"]:
            checked_values += 1
            n = _alnum(e["value"])
            if len(n) >= 4 and n in hay:
                leaks += 1; leak_by_type[e["type"]] = leak_by_type.get(e["type"], 0) + 1
        # ---- reinsertion ----
        mode = mock.last_mode
        stats = by_mode.setdefault(mode, [0, 0])
        for ph in mock.last_emitted:
            val = res.mapping.get(ph)
            if val is None:
                continue
            re_total += 1; stats[0] += 1
            if val in res.final_response:
                re_ok += 1; stats[1] += 1
        not_emitted = [v for p, v in res.mapping.items() if p not in mock.last_emitted]
        cross += sum(1 for v in not_emitted if v in res.final_response and not any(v in e for e in
                     [res.mapping[p] for p in mock.last_emitted] if v != e))   # value appears though its placeholder was never emitted
        for h in mock.last_hallucinated:
            halluc_total += 1
            halluc_safe += int(h in res.final_response and h in res.reinsertion["unresolved"])
        if mode == "drop":
            drop_cases += 1
            drop_ok += int(not any(res.mapping[p] in res.final_response for p in res.reinsertion["dropped"]))
        t = res.timings
        overhead.append(t["gateway_overhead_ms"]); llm_ms.append(t["llm_ms"]); e2e.append(t["total_ms"])

    def pct(xs, q): return round(sorted(xs)[min(len(xs) - 1, int(q * len(xs)))], 2)
    per_type = {m: {l: dict(zip(("precision", "recall", "f1"), prf(*counts[m][l])), tp=counts[m][l][0], fp=counts[m][l][1], fn=counts[m][l][2])
                    for l in ALL_LABELS} for m in counts}
    report = {
        "engine": gw.detector.engine, "documents": len(docs), "gold_entities": checked_values,
        "pii_leakage_count": leaks, "leakage_by_type": leak_by_type,
        "second_pass_catches": recheck_saves,
        "per_type_overlap": per_type["overlap"], "per_type_exact": per_type["exact"],
        "reinsertion": {"accuracy": round(re_ok / re_total, 4) if re_total else 1.0, "restored_correctly": re_ok, "total_checked": re_total,
                        "cross_person_replacements": cross, "hallucinated_placeholders_left_untouched": f"{halluc_safe}/{halluc_total}",
                        "dropped_placeholder_cases_safe": f"{drop_ok}/{drop_cases}", "by_llm_behaviour": {k: f"{v[1]}/{v[0]}" for k, v in by_mode.items()}},
        "latency_ms": {"gateway_overhead_mean": round(statistics.mean(overhead), 2), "gateway_overhead_p50": pct(overhead, .5),
                       "gateway_overhead_p95": pct(overhead, .95), "mock_llm_mean": round(statistics.mean(llm_ms), 3),
                       "end_to_end_mean": round(statistics.mean(e2e), 2)},
        "audit_chain_valid": gw.audit.verify_chain(),
    }
    os.makedirs(report_dir, exist_ok=True)
    json.dump(report, open(f"{report_dir}/metrics.json", "w"), indent=1)
    md = [f"# Privacy Gateway - Metrics Report\n", f"Engine: **{report['engine']}** | Documents: **{len(docs)}** | Gold entities: **{checked_values}**\n",
          f"## 1. PII leakage in outbound payloads\n**{leaks}** raw PII values found (target 0). By type: {leak_by_type or 'none'}. "
          f"Entities caught only by the second-pass re-scan: {recheck_saves}.\n",
          "## 2. Detection precision / recall per entity type\n| Type | Precision | Recall | F1 | TP | FP | FN | Exact P | Exact R |\n|---|---|---|---|---|---|---|---|---|"]
    for l in ALL_LABELS:
        o, x = per_type["overlap"][l], per_type["exact"][l]
        md.append(f"| {l} | {o['precision']} | {o['recall']} | {o['f1']} | {o['tp']} | {o['fp']} | {o['fn']} | {x['precision']} | {x['recall']} |")
    r = report["reinsertion"]
    md += [f"\nOverlap match = same type and IoU >= 0.5; Exact = identical span boundaries.\n",
           f"## 3. Placeholder reinsertion accuracy\n**{r['accuracy']*100:.2f}%** ({r['restored_correctly']}/{r['total_checked']}) while the LLM paraphrases, reorders, drops and hallucinates placeholders.\n",
           f"- cross-person replacements: **{r['cross_person_replacements']}**\n- hallucinated placeholders left untouched: {r['hallucinated_placeholders_left_untouched']}\n"
           f"- dropped-placeholder cases handled safely: {r['dropped_placeholder_cases_safe']}\n- by LLM behaviour: {r['by_llm_behaviour']}\n",
           f"## 4. Additional latency per request\n" + "\n".join(f"- {k}: {v} ms" for k, v in report["latency_ms"].items()),
           f"\n\nAudit hash-chain valid: **{report['audit_chain_valid']}**\n"]
    open(f"{report_dir}/metrics.md", "w").write("\n".join(md))
    print("\n".join(md))
    return report


if __name__ == "__main__":
    run()
