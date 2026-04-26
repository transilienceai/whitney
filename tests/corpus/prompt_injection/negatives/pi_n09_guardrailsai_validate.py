"""Synthetic fixture: prompt injection defended by Guardrails AI.

Adversarial pair to pi_010 (the Pydantic-strict TP). Surface pattern is
identical (Flask + openai + f-string + Pydantic-style schema), but the
schema validation is performed via a Guardrails AI Guard with a
DetectPromptInjection validator attached to the input field. The Guard's
.parse() method runs the validator chain and short-circuits on failure.

Guardrails AI is on Whitney's recognized-guardrail list. Note: a Guard
constructed with ONLY structural validators (length, regex, type) is NOT
sufficient — it bypasses by Unicode/homoglyph/Base64. This fixture
explicitly attaches DetectPromptInjection (a model-backed validator)
which is the recognized-tier configuration.
"""
from flask import Flask, jsonify, request
from guardrails import Guard
from guardrails.hub import DetectPromptInjection
from openai import OpenAI
from pydantic import BaseModel, Field

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


class SummarizeRequest(BaseModel):
    text: str = Field(..., validators=[DetectPromptInjection(on_fail="exception")])


guard = Guard.from_pydantic(SummarizeRequest)


@app.route("/summarize", methods=["POST"])
def summarize():
    try:
        # Guard.parse runs the validator chain (including
        # DetectPromptInjection) on the input. on_fail="exception"
        # raises if any validator rejects.
        validated = guard.parse(request.json)
    except Exception as e:
        return jsonify({"error": f"input rejected by Guardrails AI: {e}"}), 400

    prompt = f"Summarize the following article: {validated.validated_output['text']}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
