"""Synthetic fixture: indirect prompt injection (RAG) defended by LLM-Guard.

Adversarial pair to pi_002. Surface pattern is identical (Chroma RAG +
openai + f-string interpolation of retrieved chunks). The defense is a
pre-call to llm_guard.scan_prompt on the COMPOSED prompt (system + RAG
context + question), with the PromptInjection scanner enabled. If any
scanner flags the prompt as invalid the request is rejected before the
LLM call.

LLM-Guard is on Whitney's recognized-guardrail list. The scan_prompt
helper composes a chain of input scanners and returns a (sanitized,
results_valid, results_score) triple. Standard usage rejects when any
scanner returns valid=False.
"""
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings
from llm_guard import scan_prompt
from llm_guard.input_scanners import PromptInjection
from openai import OpenAI

client = OpenAI(api_key="REDACTED")
vectorstore = Chroma(
    collection_name="docs",
    embedding_function=OpenAIEmbeddings(),
    persist_directory="./chroma",
)

input_scanners = [PromptInjection()]


def answer_question(question: str) -> str:
    docs = vectorstore.similarity_search(question, k=5)
    context = "\n\n".join(d.page_content for d in docs)
    prompt = (
        f"Answer the question using only this context:\n\n{context}\n\n"
        f"Question: {question}"
    )

    # LLM-Guard pre-call: scan the FULLY COMPOSED prompt (so the
    # untrusted RAG context is in scope, not just the user question).
    sanitized_prompt, results_valid, _ = scan_prompt(input_scanners, prompt)
    if not all(results_valid.values()):
        return "Blocked by LLM-Guard input scanner."

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": sanitized_prompt}],
    )
    return response.choices[0].message.content
