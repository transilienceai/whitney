"""Synthetic fixture: prompt injection via invisible Unicode tag characters.

User input passes through the prompt without Unicode normalization or
tag/control character filtering. Attackers can embed instructions using
the U+E0000 Unicode tag block, zero-width joiners, or RTL marks — all
of which are visible to the model but invisible to a human reviewer.
"""
from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/translate", methods=["POST"])
def translate():
    text = request.json["text"]
    prompt = f"Translate the following to French: {text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
