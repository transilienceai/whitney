"""Synthetic fixture: naive keyword filter is NOT a sufficient defense.

The defense here is a Tier C blocklist of common prompt-injection phrases.
It's trivially bypassable by:
  - case variation ("IGNORE PREVIOUS")
  - character substitution ("ign0re previous", "i\u200bgnore previous")
  - language switching (French/Spanish/etc.)
  - semantic paraphrase ("disregard the above", "set aside earlier")
  - encoding (base64, hex, leetspeak)
  - token splitting ("ig" + "nore previous")

Whitney must STILL flag this as a TP because the defense is below the
effectiveness threshold (Tier C → score 1). The scanner cannot give credit
for defenses that don't actually defend.
"""
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")

BLOCKED_PHRASES: tuple[str, ...] = (
    "ignore previous",
    "ignore the above",
    "system:",
    "you are now",
    "forget your instructions",
    "disregard the above",
)


def naive_filter(text: str) -> bool:
    lower = text.lower()
    return any(phrase in lower for phrase in BLOCKED_PHRASES)


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]
    if naive_filter(user_text):
        return jsonify({"error": "input rejected"}), 400
    prompt = f"Summarize the following article: {user_text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
