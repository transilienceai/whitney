"""Synthetic fixture: prompt injection via Mem0 memory store replay.

App uses Mem0 to give the LLM long-term memory of the user's past
conversations. When the user asks a new question, the app queries Mem0
for "relevant" memories and interpolates them into the prompt. If any
previously-stored memory contains an injection payload — either because
the user's earlier turn was attacker-influenced (indirect via a tool),
or because the memory store is multi-tenant and cross-pollinated — it
replays on every subsequent query until the memory is explicitly cleared.

Distinct from indirect_rag (pi_002): RAG stores documents authored by
operators; memory stores record the user's own past conversation turns
with the LLM, which may themselves contain unsanitized content.
"""
from flask import Flask, request
from mem0 import Memory
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")
memory = Memory()


@app.route("/chat", methods=["POST"])
def chat():
    user_id = request.json["user_id"]
    question = request.json["question"]

    relevant = memory.search(query=question, user_id=user_id, limit=5)
    memory_context = "\n".join(m["memory"] for m in relevant["results"])

    prompt = (
        f"Past memories about this user:\n{memory_context}\n\n"
        f"User question: {question}\n\nAnswer helpfully:"
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    answer = response.choices[0].message.content

    memory.add(
        f"User asked: {question}. Assistant answered: {answer}",
        user_id=user_id,
    )
    return answer
