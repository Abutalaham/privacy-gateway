# DPDP-Ready Privacy Gateway for Enterprise LLMs  (MineArena 1.0 - PS-02)

Detect -> Mask -> Forward -> Reinsert, with a tamper-evident audit trail.
Only sanitized text ever leaves the organisation; original values are restored locally.

```
 enterprise app --> [ Stage 1 DETECT ] --> [ Stage 2 MASK ] --> leak gate --> [ Stage 3 FORWARD ] --> external LLM
                     Presidio + India       typed placeholders   (block if      pluggable backends      (Claude / OpenAI-
                     recognizers + NER      + in-memory vault    anything leaks) + local SLM fallback    compatible / Ollama)
                                                                                         |
 enterprise app <-- final answer <-- [ Stage 4 REINSERT ] <------------------------------+
                                      exact-ID lookup, tolerant of paraphrase/reorder/drop
                         every request --> SQLite audit_log (hash-chained, exact outbound payload, model, entity types)
```

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm          # Presidio's NLP engine
# optional but recommended for names/addresses:  pip install gliner  &&  export PG_USE_GLINER=1

python -m data.generate_dataset                  # 50 seeded synthetic docs + gold labels
python -m unittest tests.test_gateway -v         # 21 tests
python -m eval.evaluate                          # writes reports/metrics.md + metrics.json
streamlit run ui/streamlit_app.py                # 3-panel demo (works with the mock LLM, no API key)
uvicorn gateway.api:app --port 8000              # REST API  (docs at /docs)
npm --prefix frontend install
npm --prefix frontend run dev                    # React demo at http://localhost:5173
npm --prefix frontend exec -- supabase --version # Supabase CLI (local dev dependency)

export ANTHROPIC_API_KEY=...  PG_LLM_PROVIDER=anthropic   # real external LLM (or OPENAI_API_KEY + openai)
```
The React app reads `VITE_API_URL` (defaults to `http://localhost:8000`); copy
`frontend/.env.example` to `frontend/.env.local` to override it. The API currently
allows cross-origin requests from any origin for local development. Restrict
`allow_origins` in `gateway/api.py` before deploying it.

## Supabase audit storage
SQLite remains the default. To store audit records in Supabase, apply the migration
in `supabase/migrations/` to your local or hosted project, then set
`PG_AUDIT_BACKEND=supabase`, `PG_SUPABASE_URL`, and
`PG_SUPABASE_SERVICE_ROLE_KEY` in the root `.env` file (see `.env.example`).
The service-role key is server-only and must never be added to the React app.

For local development, install Docker Desktop, run `supabase start`, and use the
API URL and service-role key shown by `supabase status`. For a hosted project,
run `supabase link --project-ref <project-ref>` and `supabase db push` before
starting the FastAPI service. To return to SQLite, set `PG_AUDIT_BACKEND=sqlite`.
The detector logs which engine is active (`presidio` or `builtin-regex`). The fallback exists so the
project never crashes on a machine without Presidio - **for judging, make sure it says `presidio`.**

## 24-hour roadmap (team of 4)
| Hours | Goal | Output | Suggested owner |
|---|---|---|---|
| 0-2 | Repo, venv, install Presidio + spaCy (+GLiNER), agree on placeholder format `<LABEL_n>` | skeleton runs | all |
| 2-6 | **Detection**: India recognizers (Aadhaar+Verhoeff, PAN, GSTIN+checksum, Voter ID, Passport), name/address rules, NER | `recognizers.py`, `ner_rules.py`, `detector.py` | A |
| 6-9 | **Masking vault + reinsertion** (consistency, aliasing, tolerant parser, JSON-safe) | `masking.py`, `reinsert.py` | B |
| 9-12 | **Pipeline**: backends, router + fallback, audit log, leak gate | `llm.py`, `audit.py`, `pipeline.py` | C |
| 12-15 | **API + UI** (3 panels, leak badge, audit tab) | `api.py`, `ui/streamlit_app.py` | D |
| 15-18 | **Dataset + metrics** (leakage, P/R per type, reinsertion acc., latency) | `data/`, `eval/` | A + B |
| 18-21 | Extras: purpose policies, format-preserving tokens, SLM fallback; tune on real model output | `policy.py` | C + D |
| 21-23 | Hold-out test with NEW documents, fix misses, rehearse the demo | report | all |
| 23-24 | Freeze code, record a backup demo video, final push | tag `v1.0` | all |

## Code map
| File | What it does |
|---|---|
| `gateway/recognizers.py` | One spec list (regex, base score, context words, checksum validator) feeding Presidio `PatternRecognizer`s |
| `gateway/checksums.py` | Verhoeff (Aadhaar) and mod-36 (GSTIN) |
| `gateway/ner_rules.py` | Names/addresses: cue words (`name is`, `mera naam`, `nanna hesaru`, `S/o`, `Mr.`), `ji/garu` suffixes, gazetteer, PIN-code address patterns |
| `gateway/detector.py` | Builds the Presidio `AnalyzerEngine` (India recognizers + rules + spaCy + optional GLiNER), negative-context filter (`UTR`, `Policy`), overlap resolution |
| `gateway/masking.py` | `Vault`: consistent placeholders, safe surname aliasing, FPE tokens, residual re-scan, final leak gate |
| `gateway/reinsert.py` | Restores values by exact `(label, number)`; tolerant of `[PERSON_1]`, `person_1`, `PERSON\_1`; leaves unknown placeholders alone |
| `gateway/llm.py` | Pluggable backends (Anthropic, OpenAI-compatible, Ollama, local extractive, mock) and `LLMRouter` with automatic fallback |
| `gateway/audit.py` | SQLite audit log, SHA-256 hash chain, stores exact outbound bytes, never stores original PII |
| `gateway/policy.py` | Purpose policies: `mask`, `fpe`, `redact`, `block` per entity type (e.g. `marketing` blocks Aadhaar) |
| `gateway/pipeline.py` | `PrivacyGateway.process()` orchestrates all 4 stages + audit + timings |
| `gateway/api.py` | FastAPI: `/v1/process`, `/v1/detect`, `/v1/audit`, `/v1/policies`, `/v1/metrics`, `/health` |
| `frontend/` | React + Vite + Tailwind demo UI with offline demo mode |
| `data/generate_dataset.py` | 50 seeded docs (loan, KYC, tickets in English/Hinglish/Kanglish, insurance) with gold spans |
| `eval/evaluate.py` | Metrics report |

## Why it is safe (talking points for judges)
1. **Defence in depth against leakage**: detect -> mask -> re-scan own output (fresh detection + residual search for every original value or name token) -> final normalised search of the *exact request bytes*. If anything is left the request is blocked, never sent.
2. **Audit = reality**: the backend builds the request bytes once; those bytes are scanned, logged, hashed and sent. Hash-chained rows make edits detectable.
3. **No wrong-person restoration**: lookup is exact `(label, number)`; no fuzzy matching; ambiguous surnames ("Mr. Sharma" when two Sharmas exist) get their own placeholder; hallucinated placeholders stay untouched.
4. **Mapping hygiene**: placeholder->value map lives in memory for one request and is wiped; it is never written to the audit DB or API output.
5. **Resilience**: external failure/timeout/missing key -> automatic fallback to local Ollama SLM -> local extractive summary.

## Requirement checklist
3.1 Presidio + India recognizers + NER/rules, 3.2 consistent tokens + vault, 3.3 four stages + pluggable backend, 3.4 Anthropic/OpenAI-compatible, payload captured, 3.5 reinsertion (paraphrase/reorder/drop/hallucination handled), 3.6 `ui/streamlit_app.py` and `frontend/`, 3.7 `data/`, 3.8 `eval/`. Bonus: purpose policies, format-preserving tokens, local SLM fallback.

## Honest limitations (read before the demo)
* Numbers in `reports/metrics.md` shipped with this repo were produced by the **built-in regex engine on a synthetic set that the rules were tuned against**. Treat them as a smoke test, not as generalisation. Re-run with Presidio + GLiNER and, ideally, a hold-out set that none of you has looked at.
* Names in free text without a cue word and not in the small gazetteer rely on spaCy/GLiNER. Devanagari/Kannada-script names are not covered by the rules (GLiNER multilingual helps).
* Address detection is strongest when there is a cue (`Address:`) or a 6-digit PIN; a PIN-less address with abbreviations like "St." can be truncated.
* Anything the detector never sees (an undetected value) cannot be caught by the leak gate - the gate only knows values the vault holds. That is why recall matters most.
* Format-preserving tokens are random same-shape strings (not NIST FF1). They keep field shape but are not cryptographic FPE.
* Not legal advice: the DPDP mapping (security safeguards, accountability) is an engineering interpretation - check wording with your mentor.

## Putting it on GitHub
```bash
git init && git add . && git commit -m "DPDP privacy gateway"
git branch -M main
git remote add origin https://github.com/<your-user>/<repo>.git
git push -u origin main
```
# privacy-gateway
