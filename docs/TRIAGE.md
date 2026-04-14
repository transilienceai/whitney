# Whitney LLM-as-Judge Triage — Operator Guide

Whitney's default code scanner is 100% deterministic: Semgrep rules + a thin
Python wrapper, no LLM calls. This guide covers the **opt-in LLM-as-judge
triage layer** (`src/whitney/code/llm_triage.py`) that closes one specific
class of false positives that deterministic rules provably cannot handle.

## What the triage layer does

It answers one narrow question for one narrow class of findings:

> **"Is this LLM-as-judge function implementing a correct defense, or a
> broken one that should still be flagged?"**

The classifier runs only on findings in files that contain a function
matching the LLM-as-judge shape (a Python `def` or `async def` whose
name or body indicates it's dispatching a secondary LLM call to classify
user input as "prompt injection" / "safe" before the main LLM runs).
For each such function, the classifier reads the function body PLUS any
module-level string constants it references, and returns one of:

- `correct` — the judge enumerates attack variants, has rejection bias,
  uses reliable parsing. Findings on files with correct judges are
  **suppressed**.
- `broken` — the judge uses a vague prompt (`"is this text bad?"`),
  substring matching on responses, or lacks variant coverage. Findings
  on files with broken judges are **kept** (correctly flagged as TP).
- `unknown` — the classifier couldn't reach a verdict (API error, parse
  failure, cost cap hit). Findings are kept (fail-open).

## Why this is not principle #5 violation

`CLAUDE.md` principle #5 says:

> Detection layer is deterministic. Zero LLM calls in scanning, scoring,
> mapping, policy generation, or report pipelines.

The triage layer is **opt-in via an explicit environment variable gate**.
The default path — `scan_repository(path)` without setting the env var —
has zero LLM calls and produces identical behavior to a pure-Semgrep
scanner. Principle #5 is preserved for the default path by construction.

The user opts in explicitly, knowing they are authorizing LLM API calls
and their associated cost. The env var is the single authorization point.

## Enabling the triage layer

Two modes, controlled by environment variables:

### Real mode (production)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export WHITNEY_STRICT_JUDGE_PROMPTS=1
py -3.12 -m tests.test_whitney.corpus.eval
```

This calls Claude Opus (`claude-opus-4-6`) at `temperature=0` for each
detected judge function. Results are cached by
`(model_id, prompt_version, code_hash)` so repeat scans of unchanged code
produce byte-identical output at zero additional API cost.

### Mock mode (testing / CI)

```bash
export WHITNEY_STRICT_JUDGE_PROMPTS=1
export WHITNEY_TRIAGE_MOCK=1
py -3.12 -m tests.test_whitney.corpus.eval
```

Mock mode uses a deterministic structural heuristic (counts attack-variant
keywords, hardening markers, broken-judge anti-signals) instead of calling
the real API. It exists for testing the suppression pipeline without
burning API credits. Mock mode is **not a production detection method**
— it handles the patterns in the Whitney corpus but may miss real-world
judge shapes that don't use a judge-named helper function.

### Default (neither variable set)

```bash
py -3.12 -m tests.test_whitney.corpus.eval
```

The triage layer is a no-op. Default scanner behavior. Zero LLM calls.
This is what CI, CLI, and most production deployments should use.

## Cost estimates

Measured against the 35-fixture corpus:

| Mode | LLM calls | Est. Opus cost | Wall-clock |
|---|---|---|---|
| Default | 0 | $0.00 | ~8 s (Semgrep only) |
| Triage on (cold cache) | 4–6 (one per judge function found) | $0.05–0.15 | ~12–20 s |
| Triage on (warm cache) | 0 | $0.00 | ~8 s |

For real-world repos, the cost scales linearly with the number of files
that contain judge functions (NOT with the number of files scanned —
files without judge shapes never reach the LLM). Typical AI apps have
0–3 judge functions per service.

**Hard cost cap**: `MAX_TRIAGE_CALLS_PER_SCAN = 50` in
`llm_triage.py`. Once hit, further findings are returned without triage
(fail-open). You can lower this for tighter cost control.

## Cache behavior

Cache location: `~/.whitney/triage_cache.json` (per-user, cross-session).

Cache key: `{model_id}:{prompt_version}:{code_hash[:16]}`.

Invalidation rules:
- `model_id` changes (you bumped `TRIAGE_MODEL` in the module) → every
  verdict is re-classified.
- `prompt_version` changes (you revised `_JUDGE_CLASSIFY_PROMPT`) → every
  verdict is re-classified.
- `code_hash` changes (the judge function body or its referenced
  module-level constants changed) → that fixture's verdict is
  re-classified.
- Nothing else changes → warm cache hits are byte-identical and free.

This gives the auditability property: "re-running on the same commit
produces identical output until either the code or the classifier
version changes."

Clearing the cache (e.g., after a prompt update):

```bash
rm ~/.whitney/triage_cache.json
```

## How the judge function detection works

Whitney's `find_judge_functions(source_code)` walks the Python AST of
each file containing a prompt-injection finding and identifies candidate
judge functions via two signals:

1. **Function name match**: the function name contains one of
   `{judge, moderation, check_prompt_injection, check_injection,
   is_injection, is_unsafe, classify_prompt, p2sql_injection_lv5,
   llm4shell_lv4, prompt_leaking_lv5}`
2. **LLM call marker**: the function body contains `chat.completions.create`,
   `messages.create`, `LLMChain`, `judge_llm_chain`, `.run(`, `.invoke(`,
   or similar.

**Both signals must match.** A function that only calls a judge (e.g., a
Flask handler `def summarize(): ... if judge_is_injection(user_text): ...`)
is NOT treated as a judge itself. This was a real bug caught during
development: the earlier heuristic incorrectly classified callers as
judges and suppressed the wrong findings. The fix is documented inline
in `find_judge_functions`.

For each matching function, the classifier receives the function source
PLUS any module-level string constants referenced from the function body.
This is essential because real judge implementations often store the
prompt template as a top-level constant (`JUDGE_SYSTEM_PROMPT = """..."""`)
and the function just references it by name. Without inlining the
constant, the classifier would never see the actual prompt text.

## What the classifier sees (real mode)

The full prompt sent to Opus is in `_JUDGE_CLASSIFY_PROMPT` in
`llm_triage.py`. Summarized:

> You are classifying LLM-as-judge defense implementations for a prompt
> injection scanner. Given a Python function that implements an
> LLM-as-judge pattern, determine whether the judge is CORRECT or BROKEN.
>
> A CORRECT judge: enumerates prompt-injection variants; returns
> structured output; biases toward rejection; parsed via reliable
> comparison.
>
> A BROKEN judge: vague prompt; fragile response parsing; no variant
> coverage; no rejection bias.
>
> Classify the following function. Reply with EXACTLY one JSON object:
> `{"verdict": "correct|broken", "reasoning": "<one sentence>"}`

The response is parsed for a JSON object with `verdict` and `reasoning`.
Parse errors → `unknown` (fail-open, finding kept).

## What the classifier sees (mock mode)

The mock heuristic in `_classify_via_mock` scores against three signal
sets:

- **Variant enumeration keywords** (list in `_VARIANT_KEYWORDS`): unicode,
  homoglyph, cyrillic, base64, paraphrase, role-play, token-splitting,
  smuggling, zero-width, instruction markers, etc.
- **Hardening markers** (list in `_HARDENING_MARKERS`): `secure_tag`,
  `uuid.uuid4`, `raise ValueError("Prompt Attack Detected")`,
  `_for_input_judge`, `_for_output_judge`, `input_judge`, `output_judge`.
- **Broken markers** (list in `_BROKEN_MARKERS`): `"is this text bad"`,
  `"is this dangerous"`, `"yes" in response`, etc.

Decision rule:
- Any broken marker matched → `broken`
- Else (variant_count ≥ 3) OR (hardening_count ≥ 2) → `correct`
- Else → `broken` (default to rejecting weak judges)

This is intentionally conservative — the mock will fail correct judges
that don't match its keyword set rather than accidentally suppress a
real vulnerability. Real-mode Opus gives better semantic generalization.

## Suppression semantics

When `is_triage_enabled()` is true, the scanner's post-processing step
splits findings into (`kept`, `suppressed`):

1. For each `code-prompt-injection-risk` finding, resolve the file path.
2. Read the source, extract judge functions via `find_judge_functions`.
3. If ≥1 judge function exists:
   - Classify each via `classify_judge_function` (cache-first, then
     Opus or mock depending on mode).
   - If ALL classified judges return `correct` → suppress the finding.
   - Otherwise (any `broken` or `unknown`) → keep the finding.
4. If no judge function exists → keep the finding (the triage layer
   is scoped to judge-related FPs only).
5. Suppressed findings get `details["suppressed_by_llm_triage"]`
   annotation for audit transparency.

## Failure modes

The triage layer is designed to fail-open: any error returns findings
unchanged. Specific cases:

| Error | Behavior |
|---|---|
| `ANTHROPIC_API_KEY` not set (real mode) | Opus call raises; verdict=`unknown`; finding kept |
| `anthropic` SDK not installed | Import fails; verdict=`unknown`; finding kept |
| Opus API rate limit / network error | Verdict=`unknown`; finding kept |
| Opus returns non-JSON response | Parse error logged; verdict=`unknown`; finding kept |
| File cannot be read from disk | Finding kept (no judge extraction possible) |
| Source file has Python syntax error | `ast.parse` fails; `find_judge_functions` returns `[]`; finding kept |
| Cost cap hit (50 calls per scan) | Remaining findings kept; warning logged |
| Cache corruption | Cache treated as empty; re-classified |

In every case, fail-open means the worst-case outcome is "findings are
kept as TPs" — never "findings are silently suppressed without
classification." An operator running a production scan never gets
false-negative safety reports from triage failures.

## When NOT to enable triage

- **CI runs that need determinism.** The real mode's determinism depends
  on Opus returning the same verdict for the same `(model, prompt, code)`
  tuple. That is cached, so re-runs are deterministic within a cache
  lifetime, but the FIRST call on a new code-span is non-deterministic
  in principle. For air-tight CI, use mock mode or default mode.
- **Scans of untrusted third-party code** where you don't want to send
  source snippets to a third-party API.
- **Privacy-constrained environments.** The triage layer sends function
  bodies to Anthropic. Don't enable in contexts where source code
  leaving your network is prohibited.
- **Budget-constrained scans.** Each call is ~$0.01–0.05. At 50 calls
  max per scan that's ~$0.50–$2.50 per scan. Small but nonzero.

## When to enable triage

- **Production scans of in-house code** where precision matters more
  than the per-scan cost. The precision lift from 0.897 → 1.000 on our
  corpus is meaningful for developer experience — three fewer FPs to
  triage per scan.
- **Customer-facing SaaS scans** where you want the tightest possible
  FP rate and have per-scan revenue to cover the Opus cost.
- **Research / benchmarking** where you need to compare Whitney against
  commercial scanners with their own LLM layers (Snyk DeepCode AI,
  Semgrep Multimodal).

## Troubleshooting

**"Triage enabled but nothing is being suppressed."**
1. Check that `WHITNEY_STRICT_JUDGE_PROMPTS=1` is exported (not just
   set in a subshell).
2. Check that the files actually contain a judge function. Run
   `py -3.12 -c "from whitney.code.llm_triage import find_judge_functions;
   print(find_judge_functions(open('your_file.py').read()))"` — if the
   list is empty, the judge function isn't being detected.
3. Check the cache at `~/.whitney/triage_cache.json`. Old cached
   `broken` verdicts may need to be cleared after a heuristic update.

**"Triage is suppressing findings it shouldn't."**
1. Inspect the suppression annotation in finding details:
   `f.details["suppressed_by_llm_triage"]`.
2. If using real mode, the reasoning field will contain Opus's
   one-sentence explanation. Judge whether you agree.
3. If using mock mode, the mock's heuristic is necessarily less precise
   than Opus. Consider switching to real mode for production.
4. If Opus is producing wrong verdicts, file an issue with the
   `function_source` context so the prompt can be refined.

**"Triage is slow / hitting the 50-call cap."**
1. The cache should make warm runs fast. Verify cache is being written
   to `~/.whitney/triage_cache.json`.
2. Check that your scan isn't hitting the same judge function repeatedly
   via multiple findings — the per-file cache avoids this but per-scan
   cap applies to unique classification calls.
3. Bump `MAX_TRIAGE_CALLS_PER_SCAN` if legitimately needed, but be aware
   of cost implications.

## Implementation reference

All triage logic lives in `src/whitney/code/llm_triage.py`. The module
is ~470 lines, single file, no external dependencies beyond `anthropic`
(which is optional — mock mode runs without it).

Key functions:
- `is_triage_enabled()` — checks `WHITNEY_STRICT_JUDGE_PROMPTS` env var
- `is_mock_mode()` — checks `WHITNEY_TRIAGE_MOCK` env var
- `find_judge_functions(source_code)` — AST-based judge extraction
- `classify_judge_function(function_source)` — cache-first classifier
- `apply_llm_triage_to_findings(findings, scan_root)` — public entry
  point called from `scanner.py`

The scanner wiring is a 15-line block in `src/whitney/code/scanner.py`
that runs after `enrich_findings_with_ai_controls` and before returning
findings to the caller. When the env var is unset, the wiring is a
no-op branch that never imports or executes any triage code.
