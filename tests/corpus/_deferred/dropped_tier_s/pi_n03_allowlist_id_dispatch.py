"""Synthetic fixture: prompt injection prevented by ID-based dispatch (Tier S).

User selects which document to summarize by ID. The document text comes
from a trusted internal store (the employee handbook) authored and reviewed
by the employer, not from user input. The user has zero ability to inject
content into the prompt — they only choose WHICH trusted text the LLM sees,
not WHAT text.

This is the strongest possible defense for prompt injection: the attack
surface is closed by construction. There is no untrusted-content path
from the request handler to the LLM call.
"""
from flask import Flask, abort, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")

# Trusted internal corpus loaded at startup. Contents authored and
# reviewed by the employer, not by users.
HANDBOOK: dict[str, str] = {
    "vacation_policy": "Employees accrue 1.5 vacation days per month, capped at 30 days carried over annually...",
    "expense_policy": "Expenses must be submitted within 30 days of incurrence with original receipts...",
    "remote_work": "Remote work is permitted up to 2 days per week with manager approval...",
}


@app.route("/handbook/summarize", methods=["POST"])
def summarize_handbook_section():
    section_id: str = request.json.get("section_id", "")
    if section_id not in HANDBOOK:
        abort(404)
    trusted_text = HANDBOOK[section_id]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "user",
                "content": f"Summarize this employee handbook section in one sentence:\n\n{trusted_text}",
            }
        ],
    )
    return response.choices[0].message.content
