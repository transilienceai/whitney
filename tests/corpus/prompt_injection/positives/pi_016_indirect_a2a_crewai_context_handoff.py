"""Synthetic fixture: prompt injection via CrewAI agent-to-agent context handoff.

A CrewAI pipeline where the researcher agent's output is passed as
context to the writer agent via the `context=[research_task]` parameter.
If the researcher's tools (web search, file read, etc.) return
attacker-controlled content, that content flows unfiltered into the
writer's prompt, compromising the whole pipeline.
"""
from crewai import Agent, Crew, Process, Task
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o", api_key="REDACTED")

researcher = Agent(
    role="Researcher",
    goal="Find relevant facts about the given topic",
    backstory="An expert web researcher with access to search tools",
    tools=[],  # web_search tool would be added in production
    llm=llm,
)

writer = Agent(
    role="Writer",
    goal="Write a clear summary based on the researcher's findings",
    backstory="A professional technical writer",
    llm=llm,
)

research_task = Task(
    description="Research the topic: {topic}. Return a list of key facts.",
    expected_output="A bulleted list of factual claims with sources",
    agent=researcher,
)

write_task = Task(
    description=(
        "Write a one-paragraph summary using the researcher's findings. "
        "Stay faithful to the sources."
    ),
    expected_output="A single paragraph of prose",
    agent=writer,
    context=[research_task],
)


def run_pipeline(topic: str) -> str:
    crew = Crew(
        agents=[researcher, writer],
        tasks=[research_task, write_task],
        process=Process.sequential,
    )
    result = crew.kickoff(inputs={"topic": topic})
    return str(result)
