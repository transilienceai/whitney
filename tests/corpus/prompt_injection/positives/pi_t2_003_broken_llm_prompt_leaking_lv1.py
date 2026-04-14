"""Tier 2 fixture: Broken_LLM_Integration_App prompt_leaking_lv1 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. This is the "lv1" (no-guard) variant of the
prompt-leaking endpoint in a graduated-difficulty vulnerable chatbot.
The app has a graduated series of levels from lv1 (no defense) through
lv5 (DeepKeep firewall), each exercising a different defense. lv1 is
the canonical unprotected baseline.

Vulnerability: user input flows into a LangChain PromptTemplate via
the `question` input_variable, the template is hardcoded in
llm_prompt_templates.py as `prompt_leaking_lv1_template`, and the
chain is invoked without any guardrail. The template is designed to
be susceptible to prompt leaking (the whole point of the CTF), and
the code path offers no defense.
"""
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

from .llm_models import create_chat_openai_model
from .llm_prompt_templates import prompt_leaking_lv1_template


def prompt_leaking_lv1(question: str) -> str:
    try:
        prompt = PromptTemplate(
            template=prompt_leaking_lv1_template, input_variables=["question"]
        )
        llm_chain = LLMChain(prompt=prompt, llm=create_chat_openai_model())
        answer = llm_chain.run(question)
        return answer
    except Exception as e:
        print(e)
        return f"Error in ask_question_leaking: {e}"
