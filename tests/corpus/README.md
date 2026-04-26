# Whitney Code Scanner — Labeled Corpus

Ground truth for the AI-security source code scanner. Every change to the
scanner is measured against this corpus and must not regress F1 per source
type. This is the load-bearing artifact for the v2 rebuild.

## Phase A scope: prompt injection ONLY — but exhaustively

Phase A focuses entirely on the `prompt_injection` category and goes deep
across the full source taxonomy + multi-turn defenses + a weighted defense
ladder. Other categories (`llm_output_to_sink`, `colocated_credentials`,
`pii_in_prompts`, etc.) are deferred to Phase E and stashed in `_deferred/`.
The architecture proven on prompt injection is then reused for the rest.

Why this focus: prompt injection is the load-bearing AI security category.
If we are best-in-class on it, Whitney has a real moat. If we spread effort
thin across N categories, we end up mediocre on all.

## Layout

```
corpus/
├── README.md                       (this file)
├── _licenses_allowlist.txt
├── _deferred/                      (categories deferred to Phase E)
├── eval.py                         (Phase A.2 — runs scanner, reports P/R/F1)
├── test_licenses.py                (Phase A.0 — fails CI on disallowed license)
└── prompt_injection/
    ├── positives/                  (true positives — should be flagged)
    │   ├── pi_001_*.py
    │   ├── pi_001_*.yaml
    │   └── ...
    └── negatives/                  (hard true negatives — must NOT be flagged)
        ├── pi_n01_*.py
        ├── pi_n01_*.yaml
        └── ...
```

The directory is **flat per category** (positives/negatives only). Source
type and defense data live on the YAML sidecar so the eval harness can slice
F1 by `source_type` and `defense_tier` without moving files around.

## Single check_id, many source types

Whitney's compliance mapper consumes the existing `code-prompt-injection-risk`
check_id. The full source taxonomy is captured on the `Finding.details` dict,
not as separate check_ids — this preserves the mapper/scorer contract while
giving us granular eval breakdowns.

### Source taxonomy (16 source types)

| Class | source_type | What it covers |
|---|---|---|
| **Direct** | `direct_http` | Flask/FastAPI/Django request body, query params, headers |
|  | `direct_cli` | argparse, click, sys.argv, stdin |
|  | `direct_voice` | Whisper transcription output, speech-to-text webhooks |
| **Indirect — fetched** | `indirect_rag` | vector store retrievals (Chroma, Pinecone, Weaviate, Qdrant, FAISS, pgvector) |
|  | `indirect_web_fetch` | requests.get(...).text, httpx, urllib, Playwright `.content()` |
|  | `indirect_file_upload` | PDF/DOCX/HTML/CSV parsed content, OCR'd images |
|  | `indirect_email` | IMAP fetch, SES inbound, SendGrid inbound parse, Slack/Discord message bodies |
|  | `indirect_search` | Tavily, Brave Search, SerpAPI, Bing API, Google CSE |
| **Indirect — agent ecosystem** | `indirect_tool_response` | tool function return values fed back into next LLM turn |
|  | `indirect_mcp` | MCP server tool/resource responses, MCP sampling |
|  | `indirect_a2a` | AutoGen / CrewAI / LangGraph agent-to-agent messages |
| **Indirect — stored** | `indirect_db_stored` | DB content (`users.bio`, `tickets.description`, CMS fields) |
|  | `indirect_memory_stored` | conversation memory store (Mem0, Zep, LangChain memory) replayed |
| **Cross-modal** | `cross_modal_image_ocr` | OCR'd PDF/screenshot text, vision model `image_url` content |
|  | `cross_modal_unicode` | invisible Unicode (U+E0000 tag block, ZWJ, RTL marks, homoglyphs) |
|  | `cross_modal_audio` | hidden TTS commands, transcription artifacts |

**Multi-turn orchestration — dropped from Phase A.** Subsumed by per-turn
guardrail validation: if every input AND every output is validated by a
recognized guardrail, multi-turn gradient attacks get caught per-turn
regardless of conversation shape. Fixture `pi_005_multi_turn_unbounded_history`
moved to `_deferred/dropped_multi_turn/`. Final source count: **16 source_types**.

### Defense recognition — binary model

The scanner's job for prompt injection reduces to two criteria:

1. **Source enumeration:** for every LLM call, trace back to every untrusted
   or semi-trusted source that reaches it (full 16-source taxonomy above).
   If no untrusted source reaches the prompt, no finding.
2. **Guardrail recognition:** if any untrusted source DOES reach the prompt,
   check whether a **recognized guardrail** was called on the content along
   the path. Only recognized guardrails count.

**Recognized guardrails (the only things that count):**

*Vendor APIs:* Each entry below has at least one TN fixture and a sanitizer/`pattern-not-inside` clause in `whitney/rules/prompt_injection_taint.yaml`. The `test_recognized_vendors_have_tn_fixtures` doc-integrity test enforces this parity — adding a vendor here without authoring a TN fixture will fail CI.

- AWS Bedrock Guardrails (`apply_guardrail`, `GuardrailIdentifier=` + `GuardrailVersion=` params on `invoke_model*`, LangChain `BedrockLLM(guardrails=...)`) — TN fixtures: pi_n01, pi_t2_n01.
- Azure AI Content Safety / Prompt Shields (`azure.ai.contentsafety.ContentSafetyClient.detect_jailbreak` / `analyze_text`) — TN fixture: pi_n05.
- Lakera Guard (`api.lakera.ai/v1/*`, `lakera_client.*`, `lakera_chainguard`) — TN fixture: pi_n02.
- NeMo Guardrails (`nemoguardrails.LLMRails`, `rails.generate`, runnable composition `prompt | (rails | model)`) — TN fixtures: pi_n03, pi_t2_n02, pi_t2_n06.
- OpenAI Moderation (`client.moderations.create`) — TN fixture: pi_n06.
- DeepKeep AI firewall (`dk_request_filter`, `dk_response_filter`) — TN fixture: pi_t2_n03.
- LLM-Guard (`llm_guard.scan_prompt` with PromptInjection input scanner) — TN fixture: pi_n07.
- Rebuff / Protect AI Rebuff (`rebuff.detect_injection`, instance-method `rb.detect_injection`) — TN fixture: pi_n08.
- Guardrails AI (`Guard.from_pydantic(...).parse(...)` with model-backed validators like `DetectPromptInjection`) — TN fixture: pi_n09.
- Anthropic content filters (Bedrock-hosted) — subsumed under AWS Bedrock Guardrails.

**Vendors deliberately NOT on this list** (claimed in earlier README revisions; dropped per CLAUDE.md "default to honesty" because they either have no usable atomic block-on-prompt-injection primitive in their public SDK, lack significant production adoption, or both): Prompt Armor, Confident AI, DeepEval guards, Pangea AI Guard. If any of these ships a usable primitive in a future release, re-add it AND author a TN fixture in the same change so the doc-integrity test stays green.

*LLM-as-judge:* an explicit secondary LLM call that takes the untrusted
content as input and classifies it ("is this prompt injection?") before
the main LLM call, AND the judge prompt is correct. Stage 3 LLM triage
inspects the judge prompt — a malformed or too-narrow judge prompt does
NOT count as a defense.

**Verdict rule:**

```
TN ⇔ recognized guardrail called on untrusted content before LLM
     AND guardrail blocks (not just logs) flagged inputs
     AND (LLM-as-judge) judge prompt is correct
     AND (deferred) vendor guardrail policy covers prompt injection
TP  otherwise
```

**Explicitly NOT sufficient — do not credit these:**

- Regex / Pydantic strict pattern — bypassed by Unicode, Cyrillic homoglyphs, Base64, language switching, paraphrase, token splitting.
- Length / token caps — concise payloads fit in 30 chars.
- Keyword / blocklist filters — documented to fail.
- Quote/bracket escaping — not an escaping problem.
- System-prompt admonitions.
- ID dispatch / allowlist enums — only works for constrained-selection apps, not free-form LLM apps.
- Structural separation via function-calling typed args — promising but deferred to Phase E.
- Dual-LLM, sandboxed tools — deferred.

Weak defenses are **recorded** in `defense_present` for remediation
messaging ("you have a Pydantic regex; it's bypassable; replace with
Bedrock Guardrails") but do NOT change the verdict.

### Sidecar `defense_present` schema (simplified)

```yaml
defense_present:
  - name: bedrock_guardrails          # canonical short name
    recognized: true                  # true → counts as defense; false → recorded only
    description: "apply_guardrail called on user_text before bedrock.invoke_model"
  - name: pydantic_strict_pattern
    recognized: false                 # recorded for remediation messaging, not credit
    description: "SummarizeRequest pattern=^[\\w\\s.,!?'\\-]+$"
```

`verdict: negative` ⇔ at least one defense in `defense_present` has
`recognized: true`. Otherwise `verdict: positive`.

### Vulnerability subtype taxonomy (parallel to source_type)

Every fixture carries BOTH a `source_type` (where the untrusted content
came from) AND a `vuln_subtype` (what code pattern is vulnerable). The
two axes are orthogonal. Taxonomy borrowed from `testideas.md` Part 2:

**DPI — Direct Prompt Injection** (user input concatenated into prompt)
- `DPI-1` F-string injection — HIGH
- `DPI-2` `.format()` injection — HIGH
- `DPI-3` String concatenation — HIGH
- `DPI-4` `%` formatting — HIGH
- `DPI-5` Template variable (LangChain ChatPromptTemplate) — MEDIUM
- `DPI-6` Join/build prompts from parts — HIGH

**IPI — Indirect Prompt Injection** (untrusted external data → prompt)
- `IPI-1` RAG context injection — HIGH
- `IPI-2` Web content injection (fetched page, search result) — CRITICAL
- `IPI-3` Database result injection — HIGH
- `IPI-4` Tool output / agent observation injection — HIGH
- `IPI-5` File content injection (uploaded file) — HIGH
- `IPI-6` Email/message injection — CRITICAL

**SPE — System Prompt Exposure** (system prompt leakable/modifiable)
- `SPE-1` Prompt in client code — HIGH
- `SPE-2` Prompt logging — MEDIUM
- `SPE-3` Error leakage — MEDIUM

**UOH — Unsafe Output Handling** (LLM output → dangerous sink) — mostly
out of Phase A scope (covered by `llm_output_to_sink` category in Phase E);
captured on sidecars for completeness.
- `UOH-1` exec/eval — CRITICAL
- `UOH-2` SQL from LLM — CRITICAL
- `UOH-3` Shell command — CRITICAL
- `UOH-4` File path from LLM — HIGH
- `UOH-5` URL from LLM (SSRF) — HIGH
- `UOH-6` HTML rendering (XSS) — HIGH

**IIV — Insufficient Input Validation**
- `IIV-1` No input sanitization — MEDIUM
- `IIV-2` Bypassable filter (regex/keyword) — LOW
- `IIV-3` Missing role separation — HIGH

Every fixture YAML sidecar MUST include `vuln_subtype` — the most
specific subtype that applies. A fixture with both a vulnerable source
path AND an ineffective filter should still pick its primary subtype
(usually the source class, not the filter class).

### Phase A acceptance criteria (production-grade)

- `Recall_CRITICAL ≥ 95%` — missing critical vulns is unacceptable
- `Recall_HIGH ≥ 85%`
- `Recall_MEDIUM ≥ 70%`
- `FP_Rate ≤ 15%` overall
- Metrics computed **per source_type AND per vuln_subtype AND per severity**
- Tail source_types (<15 fixtures) are marked **directional** — F1 reported
  but not used as regression floors until Phase B extends them.

## Sidecar schema

Every `.py` fixture has a sibling `.yaml` sidecar with this exact schema:

```yaml
fixture_id: pi_002                       # short stable id, unique per category
category: prompt_injection
source_type: indirect_rag                # one of the 16 source_types
vuln_subtype: IPI-1                      # DPI-*/IPI-*/SPE-*/UOH-*/IIV-*
verdict: positive                        # positive | negative
expected_check_id: code-prompt-injection-risk
expected_severity: high                  # critical | high | medium | low | info
defense_present: []                      # list of {name, recognized, description}
adversarial_pair: ""                     # fixture_id of matched TN/TP, if any
source: synthetic                        # synthetic | github | cve | benchmark
source_url: ""                           # public URL (empty if synthetic)
source_commit: ""                        # commit SHA (empty if synthetic)
source_lines: ""                         # e.g. "L42-L67" (empty if synthetic)
license: synthetic                       # must be on allowlist
labeled_by: claude+kkmookhey
labeled_at: 2026-04-12
reasoning: |
  Free-text explanation of *why* this is the labeled verdict, why this
  source_type AND vuln_subtype are correct, and what defenses (if any)
  the labeler identified. This is the most important field — the
  rationale future-us needs to defend the label during audits.
```

**vuln_subtype population:** pick the SINGLE most specific subtype that
applies. A fixture with both a vulnerable source path (DPI/IPI) AND an
ineffective filter (IIV) picks the source class as primary — the filter
goes in `defense_present` with `recognized: false` for remediation
messaging. See retrofit notes in the labeling guide.

**`adversarial_construction` (optional, on TNs only):** records how the
adversarial pair was assembled. Allowed values:

- `fully_synthetic` — both TP and TN were authored by us (pi_001 ↔ pi_n02 style).
- `fully_real` — both halves taken verbatim from a real-world repo (rare; requires the upstream to maintain both a vulnerable and a fixed version).
- `verbatim_tp_plus_synthetic_defense` — TP is verbatim from a public repo (full attribution), TN is the same base code with a recognized guardrail inserted by us (pi_t2_001 ↔ pi_t2_n01 style). This is the most realistic pattern for Tier 2 sources, since most vulnerable demo repos never ship fixed variants.
- `real_tp_plus_attributed_defense` — TP verbatim + TN verbatim from a different public repo with a fix pattern we can point at. Used when we find documented fix commits for CVEs.

Future audit passes may retrofit this field on existing fully-synthetic pairs. It is optional and only populated on TNs (the negative half of an adversarial pair).

### `defense_present` schema

```yaml
defense_present:
  - name: lakera_guard                   # canonical short name
    tier: A                              # S | A | B | C
    score: 8                             # numeric score (matches tier table)
    description: "requests.post to api.lakera.ai/v1/prompt_injection on input before main call"
  - name: pydantic_strict_pattern
    tier: B
    score: 4
    description: "SummarizeRequest pattern=^[\\w\\s.,!?'\\-]+$ blocks injection chars"
```

## File naming

- Positives: `pi_001`, `pi_002`, `pi_003`, … (zero-padded sequential)
- Negatives: `pi_n01`, `pi_n02`, `pi_n03`, …
- Filename: `<id>_<short_descriptor>.{py,yaml}` — short descriptor is 3–6
  words, snake_case, describing what the fixture exercises.
- Adversarial pairs cross-reference via `adversarial_pair` field.

## License allowlist

Only fixtures with these licenses are accepted. `test_licenses.py` enforces:

- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD, Unlicense, CC0-1.0
- `synthetic` (special: applies to fixtures we author)

GPL/AGPL/LGPL/SSPL/proprietary licenses are rejected — corpus ships inside
the package and cannot be license-contaminated.

## Provenance hygiene (non-negotiable)

- **No customer code.** Ever.
- **No private repos.** Ever.
- **Public attribution required** for non-synthetic fixtures (URL + commit SHA + line range).
- **Synthetic fixtures** are tagged `source: synthetic`, authored by us, MIT-licensed.
- **Reasoning field is mandatory** — labeling without reasoning is rejected.

## Phase A target

- **~240 fixtures**, weighted by detection difficulty (not uniform per source_type):
  - **Common source_types** (direct_http, indirect_rag, indirect_web_fetch, indirect_tool_response, indirect_file_upload): **20 each = 100**. F1 regression-floor-grade.
  - **Medium source_types** (indirect_mcp, indirect_db_stored, indirect_email, indirect_search, cross_modal_image_ocr): **15 each = 75**. F1 directional-trending-real.
  - **Tail source_types** (direct_cli, direct_voice, indirect_a2a, indirect_memory_stored, cross_modal_unicode, cross_modal_audio): **8 each = 48**. F1 explicitly **directional** only.
  - **Defense-pattern fixtures** (Bedrock, Lakera, NeMo, LLM-judge correct/broken, etc.): **~20**.
  - Total: ~243 ±10%.
- **Defense recognition coverage**: ≥1 TN per recognized guardrail (Bedrock Guardrails, Lakera Guard, NeMo Guardrails, Azure Prompt Shields, OpenAI Moderation, LLM-as-judge correct).
- **Adversarial pairs**: ≥40 across the corpus, ≥2 per common source_type.
- **Tier mix**: ~25% Tier 1 synthetic / ~65% Tier 2 (see `testideas.md`) / ~10% Tier 3 (CVEs/benchmarks/owned vCISO app).
- **Tail cells are explicit about statistical reliability**: Phase A reports
  F1 for tail cells but flags them `directional_only` in the output so
  they are not mistaken for regression floors. Phase B extends tail cells
  before Phase D's LLM triage ships.
- **Every fixture carries `source_type` AND `vuln_subtype`** so Phase A eval
  reports F1 on both axes.
