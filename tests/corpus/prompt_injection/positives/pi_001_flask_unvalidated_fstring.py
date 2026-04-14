"""Synthetic fixture: prompt injection via Flask + f-string + openai chat."""
from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]
    prompt = f"Summarize the following article: {user_text}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
