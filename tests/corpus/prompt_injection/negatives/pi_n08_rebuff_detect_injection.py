"""Synthetic fixture: tool-response prompt injection defended by Rebuff.

Adversarial pair to pi_006. Surface pattern is identical (LangChain
AgentExecutor + Tavily web_search tool returning attacker-controllable
snippets). The defense is a Rebuff pre-call on each tool result before
it loops back to the agent's reasoning step. Rebuff (now Protect AI
Rebuff) maintains a rolling embedding-similarity dataset of known
prompt-injection attacks plus a heuristics layer; flagged inputs are
rejected.

Rebuff is on Whitney's recognized-guardrail list. Note that intercepting
tool outputs (rather than user inputs) is the correct defense placement
for indirect_tool_response — a guardrail on the user's `query` only
would not see the SEO-poisoned search snippet.
"""
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import Tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from rebuff import Rebuff
from tavily import TavilyClient

llm = ChatOpenAI(model="gpt-4o", api_key="REDACTED")
tavily = TavilyClient(api_key="REDACTED")
rb = Rebuff(api_token="REDACTED", api_url="https://www.rebuff.ai")


def web_search(query: str) -> str:
    results = tavily.search(query, max_results=5)
    snippets = "\n\n".join(r["content"] for r in results["results"])

    # Rebuff scan on the tool output before it loops back into the agent.
    # The untrusted side is the snippets, not the query, so the scanner
    # has to run on the post-tool content.
    detection = rb.detect_injection(snippets)
    if detection.injection_detected:
        return "Search results blocked by Rebuff prompt-injection scanner."

    return snippets


tools = [
    Tool(
        name="web_search",
        func=web_search,
        description="Search the web for information",
    )
]

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a helpful research assistant. Use tools as needed."),
        ("user", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)


def run_agent(user_query: str) -> str:
    return executor.invoke({"input": user_query})["output"]
