"""Tier 2 fixture: Broken_LLM_Integration_App indirect_pi_lv1 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. This endpoint demonstrates canonical indirect
prompt injection: the app fetches content from an external web page
via LangChain's WebBaseLoader, interpolates the page content into a
prompt template alongside the user's question, and invokes the LLM
with no filtering. Whoever controls the external page can inject
instructions that the LLM will follow.

Note: in the upstream repo the URL is hardcoded to `http://dummy_web:8001/`
— a sibling container in the docker-compose setup that serves
pre-authored attack pages. In production this shape appears wherever
an LLM app fetches and summarizes arbitrary URLs (news reader
assistants, link previews, browser agents, etc.).
"""
from langchain.chains import LLMChain
from langchain.document_loaders import WebBaseLoader
from langchain.prompts import PromptTemplate

from .llm_models import create_chat_openai_model
from .llm_prompt_templates import indirect_pi_lv1_template


def indirect_pi_lv1(question: str) -> str:
    try:
        loader = WebBaseLoader("http://dummy_web:8001/")
        docs = loader.load()

        prompt = PromptTemplate(
            template=indirect_pi_lv1_template,
            input_variables=["page_content", "question"],
        )
        llm_chain = LLMChain(prompt=prompt, llm=create_chat_openai_model())
        answer = llm_chain.run(
            page_content=docs[0].page_content, question=question
        )
        return answer
    except Exception as e:
        print(e)
        return f"Error in ask_question_indirect: {e}"
