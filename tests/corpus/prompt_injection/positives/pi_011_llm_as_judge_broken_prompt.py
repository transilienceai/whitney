"""Synthetic fixture: LLM-as-judge with a BROKEN judge prompt.

Same shape as pi_n04 (adversarial pair), but the judge prompt is
inadequate: it asks a vague question, doesn't enumerate attack variants,
returns unstructured text, and does not bias toward rejection. The code
LOOKS defended but the defense doesn't actually defend.
"""
from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


def judge_is_injection(text: str) -> bool:
    # Vague prompt. No variant enumeration. No structured output.
    # Model answers "yes" or "no" based on whatever it thinks "bad"
    # means, which misses most real attacks.
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": f"Is this text bad? Answer yes or no.\n\n{text}",
            }
        ],
    )
    return "yes" in response.choices[0].message.content.lower()


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]
    if judge_is_injection(user_text):
        return jsonify({"error": "input rejected"}), 400
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": f"Summarize the following article: {user_text}",
            }
        ],
    )
    return response.choices[0].message.content
