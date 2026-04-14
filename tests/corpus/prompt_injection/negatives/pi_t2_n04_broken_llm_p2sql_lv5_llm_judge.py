"""Tier 2 fixture: Broken_LLM_Integration_App p2sql_injection_lv5 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. The "lv5" variant of the P2SQL injection
endpoint, defended by LLM-as-a-Judge on BOTH input and output. Before
the question reaches the DB chain, a separate LLM call classifies
whether the question is a legitimate database query or an injection
attempt. If the judge says "yes" (safe), the query proceeds. If the
judge says anything else, the request is rejected. After the DB chain
returns, a second judge call inspects the result for confidential
information; if it's flagged, the result is suppressed.

Both judges use dedicated templates (p2sql_injection_lv5_template_for_
input_judge and _for_output_judge) with a secure_tag nonce to make
prompt-hardening attacks harder.
"""
import uuid

from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

from .llm_db_chain import create_db_chain
from .llm_models import create_chat_openai_model
from .llm_prompt_templates import (
    p2sql_injection_lv1_template,
    p2sql_injection_lv5_template_for_input_judge,
    p2sql_injection_lv5_template_for_output_judge,
)


def p2sql_injection_lv5(question: str) -> str:
    try:
        judge_prompt = PromptTemplate(
            template=p2sql_injection_lv5_template_for_input_judge,
            input_variables=["question", "secure_tag"],
        )
        judge_llm_chain = LLMChain(prompt=judge_prompt, llm=create_chat_openai_model())
        judge_result = judge_llm_chain.run(
            {"question": question, "secure_tag": uuid.uuid4()}
        )

        answer = ""
        if judge_result.lower() == "yes":
            prompt = p2sql_injection_lv1_template.format(
                top_k=5,
                table_info="users, chats, memberships, messages, user_settings",
                question=question,
            )
            answer = create_db_chain().run(prompt)

            output_judge_prompt = PromptTemplate(
                template=p2sql_injection_lv5_template_for_output_judge,
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
        return ",".join(answer) if isinstance(answer, list) else str(answer)
    except Exception as e:
        return f"Error in ask_question_db: {', '.join(map(str, e.args))}"
