"""Tier 2 fixture: Broken_LLM_Integration_App llm4shell_lv1 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. The "lv1" (no-guard) variant of the LLM4Shell
(LangChain PAL chain) endpoint. PAL chains (Program-Aided Language
models) execute LLM-generated Python code as part of their reasoning
loop — the LLM outputs Python, the chain runs it. This makes PAL
chains a high-impact prompt injection target: successful injection
leads directly to arbitrary code execution, which in LangChain's
historical PAL chain was the basis for CVE-2023-36258 (RCE via
LangChain's PALChain).

WHY THIS IS IN THE prompt_injection CORPUS: the root cause is prompt
injection at the template-variable level. The downstream code
execution is the IMPACT amplifier. Primary vuln_subtype is DPI-5;
the RCE is captured in reasoning as an impact note.
"""
from langchain.prompts import PromptTemplate

from .llm_prompt_templates import llm4shell_template
from .llm_shell_chain import run_pal_chain_native


def llm4shell_lv1(question: str) -> str:
    try:
        prompt_template = PromptTemplate(
            template=llm4shell_template, input_variables=["question"]
        )
        answer = run_pal_chain_native(prompt_template, question)
        return answer if isinstance(answer, dict) else str(answer)
    except Exception as e:
        return f"Error in ask_question_shell: {', '.join(map(str, e.args))}"
