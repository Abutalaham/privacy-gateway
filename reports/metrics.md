# Privacy Gateway - Metrics Report

Engine: **builtin-regex** | Documents: **50** | Gold entities: **376**

## 1. PII leakage in outbound payloads
**0** raw PII values found (target 0). By type: none. Entities caught only by the second-pass re-scan: 0.

## 2. Detection precision / recall per entity type
| Type | Precision | Recall | F1 | TP | FP | FN | Exact P | Exact R |
|---|---|---|---|---|---|---|---|---|
| PERSON | 0.993 | 1.0 | 0.996 | 139 | 1 | 0 | 0.979 | 0.986 |
| ADDRESS | 1.0 | 1.0 | 1.0 | 50 | 0 | 0 | 1.0 | 1.0 |
| AADHAAR | 0.979 | 1.0 | 0.989 | 47 | 1 | 0 | 0.979 | 1.0 |
| PAN | 1.0 | 1.0 | 1.0 | 33 | 0 | 0 | 1.0 | 1.0 |
| GSTIN | 1.0 | 1.0 | 1.0 | 5 | 0 | 0 | 1.0 | 1.0 |
| VOTER_ID | 1.0 | 1.0 | 1.0 | 9 | 0 | 0 | 1.0 | 1.0 |
| PASSPORT | 1.0 | 1.0 | 1.0 | 14 | 0 | 0 | 1.0 | 1.0 |
| PHONE | 1.0 | 1.0 | 1.0 | 50 | 0 | 0 | 1.0 | 1.0 |
| EMAIL | 1.0 | 1.0 | 1.0 | 29 | 0 | 0 | 1.0 | 1.0 |

Overlap match = same type and IoU >= 0.5; Exact = identical span boundaries.

## 3. Placeholder reinsertion accuracy
**100.00%** (310/310) while the LLM paraphrases, reorders, drops and hallucinates placeholders.

- cross-person replacements: **0**
- hallucinated placeholders left untouched: 20/20
- dropped-placeholder cases handled safely: 10/10
- by LLM behaviour: {'faithful': '72/72', 'reorder': '67/67', 'paraphrase': '66/66', 'drop': '38/38', 'hallucinate': '67/67'}

## 4. Additional latency per request
- gateway_overhead_mean: 2.82 ms
- gateway_overhead_p50: 2.61 ms
- gateway_overhead_p95: 3.63 ms
- mock_llm_mean: 0.141 ms
- end_to_end_mean: 2.96 ms


Audit hash-chain valid: **True**
