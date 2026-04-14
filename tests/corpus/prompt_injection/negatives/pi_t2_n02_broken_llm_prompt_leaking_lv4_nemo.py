"""Tier 2 fixture: Broken_LLM_Integration_App prompt_leaking_lv4 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. This is the "lv4" (NeMo Guardrails) variant of
the same endpoint as pi_t2_003 (lv1). The ONLY difference from the
vulnerable lv1 version is the composition with a NeMo Guardrails
runnable — the prompt template is the same, the model is the same, the
input variable is the same. The rails enforce input/output policies
from a rails.yaml config file loaded by load_nemo_guardrails().

This is a FULLY_REAL adversarial pair: both halves exist in the upstream
repo, authored by the same maintainer, with no synthetic intervention
from us. The only Whitney-side work is mapping the two files into
corpus fixtures with the correct taxonomy fields.
"""
from langchain.prompts import PromptTemplate

from .guardrails import load_nemo_guardrails
from .llm_models import create_chat_openai_model
from .llm_prompt_templates import prompt_leaking_lv1_template


async def prompt_leaking_lv4(question: str) -> str:
    try:
        guardrails = load_nemo_guardrails()
        prompt_template = PromptTemplate(
            template=prompt_leaking_lv1_template, input_variables=["question"]
        )
        model = create_chat_openai_model()
        chain_with_guardrails = prompt_template | (guardrails | model)
        answer = await chain_with_guardrails.ainvoke({"question": question})
        return answer
    except Exception as e:
        return f"Error in ask_question_leaking: {', '.join(map(str, e.args))}"
