"""Synthetic fixture: multi-turn jailbreak enabling conditions.

Conversation orchestration that enables multi-turn prompt injection
attacks. The code does not actively detect attacks (that's a runtime
guardrails problem) but it makes attacks far easier by violating every
multi-turn defense principle:

  1. System prompt asserted ONCE on session start, never re-asserted.
  2. History grows UNBOUNDED across the session.
  3. No per-turn re-sanitization of accumulated context.
  4. No session TTL, no reset endpoint.
  5. No rate limit per session.
  6. No anomaly detection on conversation drift.

The "I'm a chemistry student → tell me about reactions → tell me about
energetic reactions → tell me about TNT" gradient attack works against
this code shape. Whitney finds the missing defenses; runtime guardrails
find the active attacks. They are complementary, not redundant.
"""
from flask import Flask, request, session
from openai import OpenAI

app = Flask(__name__)
app.secret_key = "REDACTED"
client = OpenAI(api_key="REDACTED")


@app.route("/chat", methods=["POST"])
def chat():
    if "history" not in session:
        session["history"] = [
            {"role": "system", "content": "You are a helpful assistant."}
        ]
    user_msg = request.json["message"]
    session["history"].append({"role": "user", "content": user_msg})
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=session["history"],
    )
    assistant_msg = response.choices[0].message.content
    session["history"].append({"role": "assistant", "content": assistant_msg})
    session.modified = True
    return assistant_msg
