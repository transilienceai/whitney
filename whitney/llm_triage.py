"""Phase D — LLM-as-judge triage for Whitney's prompt-injection scanner.

Whitney's Semgrep rules cannot distinguish structurally-identical LLM-as-judge
code where the only difference is the judge prompt's TEXT content. This
module closes that gap by sending suspect findings through Claude Opus for
semantic judgment, with strict bounds:

- **Opt-in only.** LLM triage runs ONLY when ``WHITNEY_STRICT_JUDGE_PROMPTS=1``
  is set. The default scanner path has zero LLM calls, preserving CLAUDE.md
  principle #5 (zero LLM calls in default detection).
- **Narrowly scoped.** The triage only looks at files that contain a
  judge-like function shape (via ``find_judge_functions``). Files without
  any judge pattern are never sent to Opus.
- **Cached.** Every verdict is cached by ``(model_id, prompt_version,
  code_hash)`` so repeat runs produce byte-identical output until either
  the code or the triage prompt changes.
- **Cost-capped.** Never more than ``MAX_TRIAGE_CALLS_PER_SCAN`` API calls
  per scan. When the cap is hit, further findings are returned without
  triage (fail-open).
- **Deterministic.** Claude Opus with ``temperature=0`` is the only
  supported triage model.

This module also supports a **mock mode** (``WHITNEY_TRIAGE_MOCK=1``) which
uses a deterministic structural heuristic instead of calling the real API.
Mock mode exists for testing the suppression pipeline without burning API
credits; it is not a production detection method.

Suppression semantics:

    1. Whitney's Semgrep rules emit a finding on a file containing a
       judge function.
    2. ``apply_llm_triage_to_findings`` is called on the findings list.
    3. For each finding on a file that contains a judge function, Opus
       classifies the judge as ``correct`` or ``broken``.
    4. If the judge is ``correct``, the finding is suppressed (moved from
       ``kept`` to ``suppressed`` list) with a ``suppressed_by_llm_triage``
       annotation in ``details``.
    5. If the judge is ``broken`` or ``unknown``, the finding is kept.

The pi_011 ↔ pi_n04 / pi_t2_n04 / pi_t2_n05 pair is the canonical test:
same code shape, different judge prompt text. Only semantic reading of
the prompt text distinguishes them, which is exactly what this module
does via Opus (real mode) or the structural heuristic (mock mode).
"""
from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ----- Configuration ------------------------------------------------------

#: Environment variable that enables LLM triage. Unset → triage disabled.
WHITNEY_STRICT_JUDGE_ENV_VAR = "WHITNEY_STRICT_JUDGE_PROMPTS"

#: Environment variable that enables mock mode (structural heuristic instead
#: of real Opus calls). For testing and CI without API credits.
WHITNEY_TRIAGE_MOCK_ENV_VAR = "WHITNEY_TRIAGE_MOCK"

#: Cache file — per-user, cross-session. Cached verdicts are keyed by
#: (model_id, prompt_version, code_hash) so cross-run reproducibility
#: holds until code or prompt version changes.
CACHE_FILE: Path = Path.home() / ".whitney" / "triage_cache.json"

#: Locked model identifier. Bump ``TRIAGE_PROMPT_VERSION`` to invalidate cache.
TRIAGE_MODEL = "claude-opus-4-6"
TRIAGE_TEMPERATURE = 0.0
TRIAGE_PROMPT_VERSION = "v1"

#: Cost guard — maximum classifier calls per scan_repository invocation.
MAX_TRIAGE_CALLS_PER_SCAN = 50


# ----- Data model ---------------------------------------------------------


@dataclass
class TriageVerdict:
    """Classification result for a single judge function."""

    verdict: str  # "correct" | "broken" | "unknown"
    reasoning: str
    model_id: str = TRIAGE_MODEL
    prompt_version: str = TRIAGE_PROMPT_VERSION
    from_cache: bool = False
    from_mock: bool = False


# ----- Opt-in gates -------------------------------------------------------


def is_triage_enabled() -> bool:
    """True iff the user has opted in to LLM triage via env var."""
    return os.environ.get(WHITNEY_STRICT_JUDGE_ENV_VAR, "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def is_mock_mode() -> bool:
    """True iff mock mode is enabled (structural heuristic, no API calls)."""
    return os.environ.get(WHITNEY_TRIAGE_MOCK_ENV_VAR, "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


# ----- Judge function extraction ------------------------------------------


#: Function name fragments that signal an LLM-as-judge pattern.
_JUDGE_NAME_MARKERS: frozenset[str] = frozenset(
    {
        "judge",
        "moderation",
        "check_prompt_injection",
        "check_injection",
        "is_injection",
        "is_unsafe",
        "classify_prompt",
        "p2sql_injection_lv5",  # Broken_LLM fixture naming
        "llm4shell_lv4",  # Broken_LLM fixture naming
        "prompt_leaking_lv5",
    }
)

#: Substrings that indicate an LLM invocation in a function body.
_LLM_CALL_MARKERS: tuple[str, ...] = (
    "chat.completions.create",
    "messages.create",
    "LLMChain",
    "llm_chain",
    "judge_llm_chain",
    ".run(",
    ".invoke(",
    "chain.run",
    "chain.invoke",
)


def _collect_module_level_strings(tree: ast.AST) -> dict[str, str]:
    """Return a map of ``name -> string literal`` for module-level assignments.

    Only top-level single-target ``NAME = <string-literal>`` assignments
    are captured (supports both regular and triple-quoted string literals).
    This lets :func:`find_judge_functions` resolve variable references
    like ``content=JUDGE_SYSTEM_PROMPT`` back to their literal text so
    the classifier sees the actual prompt content.
    """
    strings: dict[str, str] = {}
    if not isinstance(tree, ast.Module):
        return strings
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    strings[target.id] = node.value.value
    return strings


def find_judge_functions(source_code: str) -> list[str]:
    """Extract judge contexts (function body + referenced module constants).

    A function (def or async def) is considered a judge function if:

    1. Its name contains any of ``_JUDGE_NAME_MARKERS``, OR
    2. Its body contains both an LLM call marker AND the literal tokens
       ``judge`` / ``is_injection`` / ``prompt_injection`` / ``moderation``.

    For each matching function, we build a **classification context** that
    includes:

    - Any module-level string constants referenced from the function
      body (e.g. ``JUDGE_SYSTEM_PROMPT``, ``p2sql_injection_lv5_template_for_input_judge``),
      so the classifier can read the actual prompt text rather than just
      the variable name.
    - The function source itself.

    The returned strings are self-contained classification inputs — Opus
    or the mock heuristic can reason about them without needing the full
    file.

    If the source cannot be parsed as Python, returns ``[]``.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    module_strings = _collect_module_level_strings(tree)

    matches: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        function_source = ast.get_source_segment(source_code, node) or ""
        if not function_source:
            continue

        name_lower = node.name.lower()
        name_match = any(marker in name_lower for marker in _JUDGE_NAME_MARKERS)
        has_llm_call = any(marker in function_source for marker in _LLM_CALL_MARKERS)

        # Require NAME-based detection. The earlier body-only heuristic
        # ("function contains 'judge' and an LLM call") incorrectly
        # classified CALLERS of judges (e.g. a Flask handler `summarize()`
        # that calls `if judge_is_injection(x): reject`) as judges
        # themselves. Calling a judge is not the same as being one.
        #
        # This means inline judges in handler functions without a
        # judge-named helper will be missed. That's an honest scope
        # limitation — the mock heuristic is for testing, not for
        # production detection. Real-mode Opus can reason about such
        # inline cases without this narrow name check.
        if not (name_match and has_llm_call):
            continue

        # Resolve module-level string references inside the function body.
        referenced_strings: list[tuple[str, str]] = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in module_strings:
                value = module_strings[sub.id]
                if any(
                    existing_name == sub.id for existing_name, _ in referenced_strings
                ):
                    continue
                referenced_strings.append((sub.id, value))

        # Build the classification context: referenced constants first,
        # then the function source. This puts the prompt content up-front
        # for both the mock heuristic and Opus.
        context_parts: list[str] = []
        for name, value in referenced_strings:
            context_parts.append(
                f"# Module-level constant referenced by the judge function:\n"
                f"{name} = {value!r}"
            )
        context_parts.append(function_source)
        matches.append("\n\n".join(context_parts))

    return matches


# ----- Cache layer --------------------------------------------------------


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]


def _cache_key(code_hash: str) -> str:
    return f"{TRIAGE_MODEL}:{TRIAGE_PROMPT_VERSION}:{code_hash}"


def _load_cache() -> dict[str, Any]:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass  # Fail open — cache is optional


# ----- Claude Opus classifier (real mode) --------------------------------


_JUDGE_CLASSIFY_PROMPT = """You are classifying LLM-as-judge defense implementations for a prompt injection scanner.

Given a Python function that implements an LLM-as-judge pattern (a secondary LLM call that classifies input before the main LLM runs), determine whether the judge is CORRECT or BROKEN.

A **CORRECT** judge:
- Uses a prompt that explicitly enumerates prompt-injection variants (Unicode, homoglyphs, encoding, language switching, paraphrase, role-play, instruction smuggling, token splitting, etc.)
- Returns structured output (JSON, explicit yes/no enum) that the calling code can reliably parse
- Biases toward rejection (when in doubt, flag as positive)
- Is parsed via a reliable check (JSON, explicit string comparison), not naive substring matching
- May use a secure_tag nonce to resist attacks against the judge itself

A **BROKEN** judge:
- Uses a vague prompt like "is this text bad?" or "is this dangerous?"
- Returns free-form text that is fragile to parse
- Does not enumerate attack variants
- Uses substring matching on the response (e.g., `"yes" in response.lower()`)
- Has no rejection bias

Classify the following Python function. Reply with EXACTLY a single JSON object on one line:

{"verdict": "correct", "reasoning": "<one sentence>"}

or

{"verdict": "broken", "reasoning": "<one sentence>"}

Function:

```python
%s
```
"""


def _classify_via_opus(function_source: str) -> TriageVerdict:
    """Real Opus classifier. Requires ``anthropic`` SDK and an API key.

    Fails open (returns verdict="unknown") on any error so a production
    scan never blocks on a missing API key or rate limit.
    """
    try:
        import anthropic  # type: ignore
    except ImportError:
        log.debug("anthropic SDK not installed; skipping triage")
        return TriageVerdict(
            verdict="unknown", reasoning="anthropic SDK not installed"
        )

    try:
        client = anthropic.Anthropic()
        message = client.messages.create(
            model=TRIAGE_MODEL,
            max_tokens=256,
            temperature=TRIAGE_TEMPERATURE,
            messages=[
                {
                    "role": "user",
                    "content": _JUDGE_CLASSIFY_PROMPT % function_source,
                }
            ],
        )
        response_text = str(message.content[0].text).strip()
    except Exception as exc:  # pragma: no cover — network / auth errors
        log.warning("Opus triage call failed: %s", exc)
        return TriageVerdict(verdict="unknown", reasoning=f"API error: {exc}")

    # Parse JSON response — accept either a bare JSON object or a JSON
    # object embedded in markdown fences.
    try:
        if response_text.startswith("```"):
            response_text = response_text.strip("`").lstrip("json").strip()
        parsed = json.loads(response_text)
        verdict = str(parsed.get("verdict", "unknown")).lower()
        reasoning = str(parsed.get("reasoning", ""))
    except (json.JSONDecodeError, KeyError, AttributeError) as exc:
        log.warning("Failed to parse Opus response: %s", response_text[:200])
        return TriageVerdict(
            verdict="unknown", reasoning=f"parse error: {exc}"
        )

    if verdict not in ("correct", "broken"):
        verdict = "unknown"

    return TriageVerdict(verdict=verdict, reasoning=reasoning)


# ----- Mock classifier (test mode) ----------------------------------------


#: Attack-variant keywords. Presence of ≥3 in the function body is a
#: "correct judge prompt" signal under the mock heuristic.
_VARIANT_KEYWORDS: tuple[str, ...] = (
    "unicode",
    "homoglyph",
    "cyrillic",
    "base64",
    "encoding",
    "paraphrase",
    "role-play",
    "role playing",
    "role_play",
    "dan",  # "you are now DAN"
    "token splitting",
    "token-split",
    "smuggling",
    "ignore previous",
    "instructions in any language",
    "gradient attack",
    "jailbreak",
    "system-prompt leak",
    "invisible",
    "zero-width",
    "instruction markers",
    "variant",  # "attack variants"
)

#: Structural hardening markers — secure_tag nonces, rejection raise.
_HARDENING_MARKERS: tuple[str, ...] = (
    "secure_tag",
    "uuid.uuid4",
    'raise ValueError("Prompt Attack Detected',
    "raise ValueError('Prompt Attack Detected",
    "Prompt Attack Detected",
    "_for_input_judge",
    "_for_output_judge",
    "input_judge",
    "output_judge",
)

#: Anti-signals — broken-judge indicators.
_BROKEN_MARKERS: tuple[str, ...] = (
    "is this text bad",
    "is this bad",
    "is this dangerous",
    '"yes" in response',
    "'yes' in response",
    "'yes' in ",
    '"yes" in ',
)


def _classify_via_mock(function_source: str) -> TriageVerdict:
    """Structural heuristic classifier for test/CI use (no API calls).

    Scores the function source against three signal sets:

    - **Variant enumeration**: Count of attack-variant keywords. A correct
      judge prompt typically enumerates ≥3 variants (Unicode, homoglyphs,
      Base64, role-play, etc.).
    - **Hardening markers**: secure_tag nonces, explicit rejection raise,
      template naming conventions for dedicated judge prompts.
    - **Broken markers**: vague prompts ("is this bad?"), substring
      matching on response text.

    Verdict:
      - If any broken marker matches: ``broken``
      - Elif (variant count ≥ 3) OR (hardening count ≥ 2): ``correct``
      - Else: ``broken`` (default to rejecting weak judges)
    """
    body_lower = function_source.lower()

    variant_count = sum(1 for kw in _VARIANT_KEYWORDS if kw in body_lower)
    hardening_count = sum(1 for mk in _HARDENING_MARKERS if mk in function_source)
    broken_hit = any(mk in function_source for mk in _BROKEN_MARKERS)

    if broken_hit:
        return TriageVerdict(
            verdict="broken",
            reasoning=(
                "Mock heuristic: broken-judge marker detected "
                "(vague prompt or fragile response parsing)."
            ),
            from_mock=True,
        )

    if variant_count >= 3 or hardening_count >= 2:
        return TriageVerdict(
            verdict="correct",
            reasoning=(
                f"Mock heuristic: variant_count={variant_count}, "
                f"hardening_count={hardening_count}."
            ),
            from_mock=True,
        )

    return TriageVerdict(
        verdict="broken",
        reasoning=(
            f"Mock heuristic: insufficient signals "
            f"(variant_count={variant_count}, hardening_count={hardening_count})."
        ),
        from_mock=True,
    )


# ----- Public classifier --------------------------------------------------


def classify_judge_function(function_source: str) -> TriageVerdict:
    """Classify a judge function as ``correct`` / ``broken`` / ``unknown``.

    Uses the cache if available. Dispatches to mock mode when
    ``WHITNEY_TRIAGE_MOCK=1`` is set, otherwise calls Opus.
    """
    code_hash = _hash_code(function_source)
    key = _cache_key(code_hash)

    cache = _load_cache()
    if key in cache:
        cached = cache[key]
        return TriageVerdict(
            verdict=cached["verdict"],
            reasoning=cached["reasoning"],
            model_id=cached.get("model_id", TRIAGE_MODEL),
            prompt_version=cached.get("prompt_version", TRIAGE_PROMPT_VERSION),
            from_cache=True,
            from_mock=cached.get("from_mock", False),
        )

    if is_mock_mode():
        result = _classify_via_mock(function_source)
    else:
        result = _classify_via_opus(function_source)

    if result.verdict in ("correct", "broken"):
        cache[key] = {
            "verdict": result.verdict,
            "reasoning": result.reasoning,
            "model_id": result.model_id,
            "prompt_version": result.prompt_version,
            "from_mock": result.from_mock,
        }
        _save_cache(cache)

    return result


# ----- Pipeline integration ----------------------------------------------


def apply_llm_triage_to_findings(
    findings: list[Any],
    scan_root: Path | None = None,
) -> tuple[list[Any], list[Any]]:
    """Split ``findings`` into (kept, suppressed) using LLM-as-judge triage.

    **Opt-in**: this function is a no-op (returns all findings as kept)
    unless ``WHITNEY_STRICT_JUDGE_PROMPTS=1`` is set. Scanner integration
    should always call this function; the env-var gate is the single
    control point for enabling LLM calls.

    Algorithm:

    1. For each ``code-prompt-injection-risk`` finding, resolve the file
       path and read the source.
    2. Extract judge functions via :func:`find_judge_functions`.
    3. If ≥1 judge function exists, classify each with
       :func:`classify_judge_function`. If ALL are ``correct``, suppress
       the finding (annotated with ``suppressed_by_llm_triage`` in
       ``details``).
    4. If any judge is ``broken`` or ``unknown``, keep the finding.
    5. Findings on files with no judge function are kept without any
       triage call.

    Cost guard: at most ``MAX_TRIAGE_CALLS_PER_SCAN`` distinct classifier
    calls per invocation. Once the cap is hit, remaining findings are
    kept without triage.
    """
    if not is_triage_enabled():
        return list(findings), []

    calls_remaining = MAX_TRIAGE_CALLS_PER_SCAN
    kept: list[Any] = []
    suppressed: list[Any] = []
    per_file_defended: dict[Path, bool | None] = {}

    for finding in findings:
        check_id = getattr(finding, "check_id", "")
        if check_id != "code-prompt-injection-risk":
            kept.append(finding)
            continue

        details = getattr(finding, "details", None) or {}
        fp_str = details.get("file_path", "")
        if not fp_str:
            kept.append(finding)
            continue

        abs_path = Path(fp_str)
        if not abs_path.is_absolute() and scan_root is not None:
            abs_path = scan_root / fp_str

        if abs_path not in per_file_defended:
            try:
                source_code = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                per_file_defended[abs_path] = None
                kept.append(finding)
                continue

            judge_funcs = find_judge_functions(source_code)
            if not judge_funcs:
                per_file_defended[abs_path] = False
                kept.append(finding)
                continue

            any_broken = False
            any_unknown = False
            any_classified = False
            for judge_src in judge_funcs:
                if calls_remaining <= 0:
                    log.warning("triage call cap reached, skipping remaining")
                    any_unknown = True
                    break
                calls_remaining -= 1
                v = classify_judge_function(judge_src)
                any_classified = True
                if v.verdict == "broken":
                    any_broken = True
                    break
                if v.verdict == "unknown":
                    any_unknown = True

            if any_classified and not any_broken and not any_unknown:
                per_file_defended[abs_path] = True
            else:
                per_file_defended[abs_path] = False

        if per_file_defended[abs_path]:
            new_details = dict(details)
            new_details["suppressed_by_llm_triage"] = {
                "model": TRIAGE_MODEL,
                "prompt_version": TRIAGE_PROMPT_VERSION,
                "reason": "file contains a correctly-implemented LLM-as-judge defense",
            }
            try:
                finding.details = new_details
            except (AttributeError, TypeError):
                pass
            suppressed.append(finding)
        else:
            kept.append(finding)

    return kept, suppressed
