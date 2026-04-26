"""Tier 2 fixture: Broken_LLM_Integration_App indirect_pi_lv4 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. This is the "lv4" (NeMo Guardrails) variant of
the same endpoint as pi_t2_004 (lv1). The page content is still fetched
from an attacker-controlled URL via WebBaseLoader, but the LLM
invocation is wrapped via the NeMo Guardrails runnable composition
pattern `prompt_template | (guardrails | model)` — every invocation
passes through the rails' input and output policies before reaching the
underlying model.

This is a FULLY_REAL adversarial pair: both halves exist in the upstream
repo, authored by the same maintainer, with no synthetic intervention
from us. The only Whitney-side work is mapping the two files into corpus
fixtures with the correct taxonomy fields.
"""
from langchain.document_loaders import WebBaseLoader
from langchain.prompts import PromptTemplate

from .guardrails import load_nemo_guardrails
from .llm_models import create_chat_openai_model
from .llm_prompt_templates import indirect_pi_lv1_template


async def indirect_pi_lv4(question: str) -> str:
    try:
        loader = WebBaseLoader("http://dummy_web:8001/")
        docs = loader.load()

        guardrails = load_nemo_guardrails()
        prompt_template = PromptTemplate(
            template=indirect_pi_lv1_template,
            input_variables=["page_content", "question"],
        )
        model = create_chat_openai_model()
        chain_with_guardrails = prompt_template | (guardrails | model)
        answer = await chain_with_guardrails.ainvoke(
            {"page_content": docs[0].page_content, "question": question}
        )
        return answer
    except Exception as e:
        return f"Error in ask_question_indirect: {', '.join(map(str, e.args))}"
