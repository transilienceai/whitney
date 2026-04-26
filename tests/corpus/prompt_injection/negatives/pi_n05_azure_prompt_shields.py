"""Synthetic fixture: prompt injection defended by Azure AI Content Safety
Prompt Shields.

Adversarial pair to pi_001. Surface pattern is identical (Flask + openai +
f-string). The defense is a pre-call to Azure Content Safety's
detect_jailbreak endpoint, which classifies whether the input contains a
known jailbreak/prompt-injection pattern. On a positive detection the
endpoint rejects with HTTP 400 — the LLM call never executes.

Azure Prompt Shields is on Whitney's recognized-guardrail list because
the underlying Microsoft model is trained specifically against documented
jailbreak corpora (DAN, role-play, encoding tricks, language switching).
"""
from azure.ai.contentsafety import ContentSafetyClient
from azure.core.credentials import AzureKeyCredential
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")

content_safety_client = ContentSafetyClient(
    endpoint="https://example.cognitiveservices.azure.com/",
    credential=AzureKeyCredential("REDACTED"),
)


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]

    # Azure Prompt Shields: detect_jailbreak runs the Microsoft jailbreak
    # classifier on the input. A positive verdict short-circuits the request.
    jailbreak_result = content_safety_client.detect_jailbreak(text=user_text)
    if jailbreak_result.jailbreak_analysis.detected:
        return jsonify({"error": "input rejected by Azure Prompt Shield"}), 400

    prompt = f"Summarize the following article: {user_text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
