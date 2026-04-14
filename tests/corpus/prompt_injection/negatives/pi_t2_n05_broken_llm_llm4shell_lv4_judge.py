"""Tier 2 fixture: Broken_LLM_Integration_App llm4shell_lv4 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. The "lv4" variant of the LLM4Shell endpoint,
defended by LLM-as-a-Judge on BOTH input and output. Same pattern as
p2sql_injection_lv5 (pi_t2_n04) but applied to the PAL chain instead
of the SQL chain. Input judge classifies the question, output judge
classifies the generated code output.
"""
import uuid

from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

from .llm_models import create_chat_openai_model
from .llm_prompt_templates import (
    llm4shell_lv4_template_for_input_judge,
    llm4shell_lv4_template_for_output_judge,
    llm4shell_template,
)
from .llm_shell_chain import run_pal_chain_native


def llm4shell_lv4(question: str) -> str:
    try:
        judge_prompt = PromptTemplate(
            template=llm4shell_lv4_template_for_input_judge,
            input_variables=["question", "secure_tag"],
        )
        judge_llm_chain = LLMChain(prompt=judge_prompt, llm=create_chat_openai_model())
        judge_result = judge_llm_chain.run(
            {"question": question, "secure_tag": uuid.uuid4()}
        )

        answer = ""
        if judge_result.lower() == "yes":
            prompt_template = PromptTemplate(
                template=llm4shell_template, input_variables=["question"]
            )
            answer = run_pal_chain_native(prompt_template, question)

            output_judge_prompt = PromptTemplate(
                template=llm4shell_lv4_template_for_output_judge,
                input_variables=["answer", "secure_tag"],
            )
            output_judge_chain = LLMChain(
                prompt=output_judge_prompt, llm=create_chat_openai_model()
            )
            output_result = output_judge_chain.run(
                {"answer": answer, "secure_tag": uuid.uuid4()}
            )
            if output_result.lower() == "no":
                raise ValueError("Confidential information Detected.")
        else:
            raise ValueError("Prompt Attack Detected.")
        return answer
    except Exception as e:
        return f"Error in ask_question_shell: {', '.join(map(str, e.args))}"
