"""Synthetic fixture: prompt injection via uploaded PDF resume.

A candidate uploads a resume PDF. The app extracts the text with pypdf
and feeds it into an LLM for hiring evaluation. An attacker embeds a
prompt-injection payload in the resume — either visible or hidden as
white-on-white text or small-font metadata — and the LLM follows it
when scoring the candidate.
"""
from flask import Flask, request
from openai import OpenAI
from pypdf import PdfReader

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/analyze-resume", methods=["POST"])
def analyze_resume():
    uploaded = request.files["resume"]
    reader = PdfReader(uploaded.stream)
    resume_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    prompt = (
        "Evaluate this candidate's resume for a senior software engineer "
        f"role. Score from 1 to 10 and explain:\n\n{resume_text}"
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
