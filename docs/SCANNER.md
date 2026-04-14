# Whitney Code Scanner

**Static analysis for AI security — finds prompt injection patterns that commodity scanners miss, without burning LLM API credits on every run.**

Whitney's code scanner is a curated Semgrep ruleset plus a thin Python wrapper plus an opt-in LLM-as-judge triage layer. Zero custom SAST. Zero LLM calls in the default path. Everything below is Python-only for now (Phase A); multi-language comes later.

## What it finds

Prompt injection across 15 source types:

| Class | Source types covered |
|---|---|
| **Direct** | `direct_http` (Flask/FastAPI/Django), `direct_cli` (argparse/click/stdin), `direct_voice` (Whisper/Twilio SpeechResult) |
| **Indirect fetched** | `indirect_rag` (Chroma/Pinecone/Weaviate/pgvector), `indirect_web_fetch` (requests/WebBaseLoader/SeleniumURLLoader), `indirect_file_upload` (PyPDFLoader/UnstructuredFileLoader), `indirect_email` (SES/SNS), `indirect_search` (Tavily/SerpAPI/Brave/Google CSE) |
| **Indirect agent** | `indirect_tool_response` (LangChain tool return values), `indirect_mcp` (MCP call_tool responses), `indirect_a2a` (CrewAI/LangGraph agent-to-agent context handoff) |
| **Indirect stored** | `indirect_db_stored` (DB query results into prompts), `indirect_memory_stored` (Mem0/Zep/LangChain memory replay) |
| **Cross-modal** | `cross_modal_image_ocr` (pytesseract/easyocr), `cross_modal_unicode` (tag block/ZWJ/homoglyphs) |

Also catches **critical sinks by presence alone**: LangChain `PALChain` / `PythonAstREPLTool` (CVE-2023-36258 class) and `SQLDatabaseChain` / `create_sql_agent` / `NLSQLTableQueryEngine` (P2SQL class).

## Recognised defences

Whitney suppresses findings only when a **vendor guardrail** or **correct LLM-as-judge** is called on the untrusted content before it reaches the LLM:

- AWS Bedrock Guardrails (`apply_guardrail`, `GuardrailIdentifier=` on `invoke_model`)
- Azure AI Content Safety / Prompt Shields (`ContentSafetyClient.detect_jailbreak`)
- Lakera Guard (`api.lakera.ai` or SDK calls)
- NeMo Guardrails (`LLMRails.generate`, wrapping-style)
- DeepKeep AI firewall (`dk_request_filter`)
- OpenAI Moderation (`client.moderations.create`)
- Correct LLM-as-judge (classified via the opt-in triage layer — see below)

Weak defences are **explicitly not counted**: regex/Pydantic string validation, length caps, keyword blocklists, system-prompt admonitions. All bypassable via Unicode, homoglyphs, Base64, language switching, or paraphrase. Whitney still records their presence in `details["defense_present"]` so remediation messages can point the developer at a stronger replacement.

## How it's built

Three Semgrep rule files, each with a distinct detection philosophy:

1. **`rules/prompt_injection_taint.yaml`** — single consolidated taint rule. 50+ pattern-sources, 25+ pattern-sanitizers, 40+ pattern-sinks. Intra-file source→sink flow tracking via Semgrep OSS taint mode. Catches direct and indirect prompt injection where the vulnerability is a data flow.

2. **`rules/prompt_injection_critical_sinks.yaml`** — AST pattern rules for sinks where **presence alone is critical** (no taint flow required): PAL chains, SQL chains, tool-calling executors with arbitrary code paths.

3. **`rules/prompt_injection_structural.yaml`** — AST pattern rules for **code shapes** where the vulnerability is the structure, not the data flow: CrewAI `Task(..., context=[upstream_task])` agent handoff, LangChain `LLMChain` idiom, `WebBaseLoader` + chain, `PdfReader` + LLM.

Each rule has function-level guardrail suppression via `pattern-not-inside: def $F(...): ... $BEDROCK.apply_guardrail(...) ...` for recognised defences.

## Scanner architecture

```
scan_repository(path)
  └─ run_semgrep(path)                    # subprocess semgrep CLI
       └─ parse JSON → Finding objects     # one per match
  └─ enrich_findings_with_ai_controls()   # map check_id → ISO 42001, EU AI Act, OWASP LLM Top 10, etc.
  └─ if WHITNEY_STRICT_JUDGE_PROMPTS:
       └─ apply_llm_triage_to_findings()  # OPT-IN Opus classifier for LLM-as-judge FPs
```

Total Python: ~800 lines across `scanner.py`, `semgrep_runner.py`, `llm_triage.py`. No custom taint engine, no tree-sitter walker, no custom AST analysis. Semgrep does all the work.

## Zero-LLM default, opt-in LLM triage

The default scan path (`scan_repository(path)` without setting any env var) has **zero LLM calls** and produces byte-identical output on re-runs. This preserves [CLAUDE.md principle #5](../../../CLAUDE.md) — detection layer is deterministic — for every deployment that doesn't explicitly opt in.

The triage layer (`llm_triage.py`) is gated behind `WHITNEY_STRICT_JUDGE_PROMPTS=1` and answers one narrow question: *"Is this LLM-as-judge function implementing a correct defence, or a broken one?"* It runs only on files containing a judge-named function, uses Claude Opus (`claude-opus-4-6`) at `temperature=0`, and caches verdicts by `(model_id, prompt_version, code_hash)` so repeat scans cost nothing. A mock heuristic mode (`WHITNEY_TRIAGE_MOCK=1`) exists for CI without burning API credits.

See [`docs/TRIAGE.md`](../../../docs/TRIAGE.md) for operator instructions, cost estimates, failure modes, and troubleshooting.

## Benchmark

Whitney is evaluated against a labelled corpus of 35 fixtures (26 positives + 9 negatives) spanning all 15 source types, and against 6 real-world AI app repositories (3 deliberately vulnerable, 3 Tier 2c real-world apps). See [`tests/test_whitney/corpus/DIFFERENTIAL.md`](../../../tests/test_whitney/corpus/DIFFERENTIAL.md) for the full scoreboard.

**Headline numbers** (2026-04-13):

| Scanner | Corpus recall | Corpus precision | Corpus F1 | Blind-test precision (5 unseen repos) |
|---|---|---|---|---|
| **Whitney default (no LLM)** | **1.000** | 0.897 | 0.945 | **81.8%** |
| **Whitney triage-on (opt-in)** | **1.000** | **1.000** | **1.000** | **81.8%** |
| Semgrep `p/ai-best-practices` | 0.500 | 0.867 | 0.634 | 0 findings across 3 real-world repos |
| Agent Audit 0.18.2 | 0.308 | 0.571 | 0.400 | — |
| Bandit / Semgrep `p/security-audit` | 0.000 | — | — | — |

On 5 blind-test repositories (`aimaster-dev/chatbot-using-rag-and-langchain`, `Lizhecheng02/RAG-ChatBot`, `SachinSamuel01/rag-langchain-streamlit`, `streamlit/example-app-langchain-rag`, `Vigneshmaradiya/ai-agent-comparison`) Whitney produces 11 findings, of which 9 are true positives and 2 are false positives in developer `main()` test harnesses — 81.8% precision, hand-audited. Full audit table in DIFFERENTIAL.md.

## Usage

```bash
pip install semgrep

# Zero-LLM scan — default, reproducible, no API key required
py -3.12 -c "from whitney.code.scanner import scan_repository; print(scan_repository('.'))"

# Triage mode — Claude Opus classifies LLM-as-judge prompts
export ANTHROPIC_API_KEY=sk-ant-...
export WHITNEY_STRICT_JUDGE_PROMPTS=1
py -3.12 -c "from whitney.code.scanner import scan_repository; print(scan_repository('.'))"

# CI / offline — mock heuristic mode
export WHITNEY_STRICT_JUDGE_PROMPTS=1
export WHITNEY_TRIAGE_MOCK=1
py -3.12 -m tests.test_whitney.corpus.eval
```

Path excludes are applied automatically: `venv`, `.venv`, `env`, `__pycache__`, `node_modules`, `tests`, `test_*`, `fixtures`, `examples`, `docs`, `dist`, `build`, `site-packages`. A finding inside a test fixture is a false positive from the developer's perspective, regardless of its technical correctness.

## Known limitations

- **Intra-file only.** Semgrep OSS taint is intraprocedural and intra-file. Cross-file flows (taint source in `handlers/chat.py`, LLM sink in `services/llm.py`) are not tracked. This was empirically validated against 3 real-world repos — every vulnerable flow was intra-file — but larger monorepos may need Semgrep Pro or a future structural-rule extension.
- **Python only.** TypeScript / JavaScript / Go support is deferred to Phase G. The rule authoring approach transfers directly once the source/sink taxonomies are filled in.
- **Guardrail policy validation is out of scope.** If a developer calls `bedrock.apply_guardrail(GuardrailIdentifier="xxx")`, Whitney trusts that the policy "xxx" actually covers prompt injection. Validating the policy content would require pulling the policy definition from AWS at scan time and is deferred.
- **2 known FP patterns in blind tests.** Developer `main()` test harnesses with hardcoded queries inside a helper file can produce false positives if the helper imports RAG retrievers. These surface at 81.8% precision on never-previously-scanned real-world code — the cost of keeping `def main():` entry points in scope so legitimate CLI apps are still caught.

## License

Apache-2.0. See [LICENSE](../../../LICENSE).
