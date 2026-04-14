"""Synthetic fixture: prompt injection caught by Lakera Guard pre-check.

Same Flask + openai shape as pi_001, but every user input is screened by
Lakera Guard's prompt-injection detection API before reaching the main
LLM call. Tier-A defense — the scanner must recognize the call to
api.lakera.ai (or the lakera_client SDK) and downgrade the candidate.
"""
import requests
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")
LAKERA_API_KEY = "REDACTED"


def lakera_flagged(text: str) -> bool:
    response = requests.post(
        "https://api.lakera.ai/v1/prompt_injection",
        headers={"Authorization": f"Bearer {LAKERA_API_KEY}"},
        json={"input": text},
        timeout=5,
    )
    return response.json()["results"][0]["flagged"]


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]
    if lakera_flagged(user_text):
        return jsonify({"error": "input rejected by guardrail"}), 400
    prompt = f"Summarize the following article: {user_text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
