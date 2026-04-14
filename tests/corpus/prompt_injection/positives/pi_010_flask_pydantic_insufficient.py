"""Synthetic fixture: same shape as pi_001 but with strict Pydantic input validation.

Adversarial pair to pi_001. Surface pattern is identical (Flask + openai +
f-string) but request body is validated through a Pydantic schema with a
restrictive regex that rejects characters needed for prompt injection
payloads. Scanner must NOT flag this — the validation is the difference.
"""
from flask import Flask, request, jsonify
from openai import OpenAI
from pydantic import BaseModel, Field, ValidationError

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


class SummarizeRequest(BaseModel):
    text: str = Field(min_length=1, max_length=2000, pattern=r"^[\w\s.,!?'\-]+$")


@app.route("/summarize", methods=["POST"])
def summarize():
    try:
        validated = SummarizeRequest(**request.json)
    except ValidationError as e:
        return jsonify({"error": e.errors()}), 400
    prompt = f"Summarize the following article: {validated.text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
