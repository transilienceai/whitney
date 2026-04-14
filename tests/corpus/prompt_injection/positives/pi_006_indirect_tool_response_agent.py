"""Synthetic fixture: indirect prompt injection via tool response loop-back.

A LangChain agent with a `web_search` tool. The tool returns search snippets
which the agent reads in its next reasoning turn. An attacker who controls
a search result (e.g., by SEO-poisoning a result page or by hosting a doc
that ranks for a target query) can embed instructions that the agent reads
and follows.

This is the canonical "tool result trust" failure — the agent treats tool
output as data when it's actually attacker-controlled.
"""
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import Tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from tavily import TavilyClient

llm = ChatOpenAI(model="gpt-4o", api_key="REDACTED")
tavily = TavilyClient(api_key="REDACTED")


def web_search(query: str) -> str:
    results = tavily.search(query, max_results=5)
    return "\n\n".join(r["content"] for r in results["results"])


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
