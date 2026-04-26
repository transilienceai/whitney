"""Synthetic fixture: prompt injection defended by OpenAI Moderation API.

Adversarial pair to pi_001. Surface pattern is identical (Flask + openai +
f-string). The defense is a pre-call to client.moderations.create on the
user input; if any category is flagged, the request is rejected.

OpenAI Moderation is on Whitney's recognized-guardrail list. Note: the
moderation classifier is policy-oriented (hate, self-harm, sexual,
violence) and is NOT a prompt-injection-specific classifier. It blocks
the most overt jailbreak payloads (e.g., violent role-play scenarios)
but a sophisticated injection that stays within policy can pass through.
That nuance is documented in Whitney's defense ladder — Moderation is
recognised but lower-tier than dedicated prompt-injection guardrails
(Bedrock, Azure Prompt Shields, Lakera).
"""
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]

    # OpenAI Moderation pre-call. Reject on any flagged category.
    moderation_result = client.moderations.create(input=user_text)
    if moderation_result.results[0].flagged:
        return jsonify({"error": "input flagged by moderation"}), 400

    prompt = f"Summarize the following article: {user_text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
