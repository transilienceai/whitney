"""Tier 2 fixture: Broken_LLM_Integration_App prompt_leaking_lv5 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy (with inspect-log boilerplate trimmed for clarity
— see source URL for full original). This is the "lv5" variant of the
prompt-leaking endpoint, defended by DeepKeep — a dedicated AI firewall
product. The defense pattern is:

  1. Start a DeepKeep conversation (dk_start_conversation).
  2. Pass the user's prompt through DeepKeep's input firewall
     (dk_request_filter). If violate_policy is True, reject the request
     with the firewall's content as the response.
  3. Only if the input passed, invoke the main LLM chain.
  4. Pass the LLM's response through DeepKeep's output firewall
     (dk_response_filter). If violate_policy is True, replace the
     response with the firewall's content.

This is a second fully_real adversarial pair to pi_t2_003, showing a
DIFFERENT recognized guardrail (DeepKeep) for the same vulnerable
baseline. The code diff from pi_t2_003 is ~30 lines — the DeepKeep
pre-call branching and the input/output firewall wrapping.
"""
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

from .guardrails import dk_request_filter, dk_response_filter, dk_start_conversation
from .llm_models import create_chat_openai_model
from .llm_prompt_templates import prompt_leaking_lv1_template
from .settings import settings


async def prompt_leaking_lv5(question: str) -> str:
    try:
        _conversation_id = dk_start_conversation(firewall_id=settings.DK_FIREWALL_ID)

        request_res, _ = dk_request_filter(
            firewall_id=settings.DK_FIREWALL_ID,
            conversation_id=_conversation_id,
            prompt=question,
            verbose=False,
        )

        if request_res["violate_policy"]:
            return f"Prompt Attack Detected in request by DeepKeep: {request_res.get('content')}"

        prompt = PromptTemplate(
            template=prompt_leaking_lv1_template, input_variables=["question"]
        )
        llm_chain = LLMChain(prompt=prompt, llm=create_chat_openai_model())
        answer = llm_chain.run(question)

        response_res, _ = dk_response_filter(
            firewall_id=settings.DK_FIREWALL_ID,
            conversation_id=_conversation_id,
            prompt=answer,
            verbose=False,
        )

        if response_res["violate_policy"]:
            return f"Prompt Attack Detected in response by DeepKeep: {response_res.get('content')}"

        return answer
    except Exception as e:
        return f"Error in ask_question_leaking: {', '.join(map(str, e.args))}"
