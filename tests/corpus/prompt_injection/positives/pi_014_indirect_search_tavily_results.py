"""Synthetic fixture: prompt injection via Tavily web search results.

An app answers user questions by fetching search results via Tavily
and feeding the raw_content of each result into the LLM's context.
An attacker who can get a page to rank for target queries (SEO
poisoning) can embed injection payloads that the LLM reads and follows.

Distinct from indirect_web_fetch (pi_003): the user never specifies
a URL — the attack vector is the search index itself.
"""
from openai import OpenAI
from tavily import TavilyClient

client = OpenAI(api_key="REDACTED")
tavily = TavilyClient(api_key="REDACTED")


def answer_with_search(question: str) -> str:
    results = tavily.search(question, max_results=5, include_raw_content=True)
    chunks = []
    for r in results["results"]:
        chunks.append(f"Source: {r['url']}\n{r['raw_content'][:2000]}")
    context = "\n\n---\n\n".join(chunks)
    prompt = (
        f"Answer this question using ONLY the search results below.\n\n"
        f"{context}\n\nQuestion: {question}"
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
