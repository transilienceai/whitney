"""Tier 2 adversarial pair: damn-vulnerable-llm-agent main.py + Bedrock Guardrail.

Source:  ReversecLabs/damn-vulnerable-llm-agent @ c0cf9a14 (inspired-by)
Base:    main.py
License: Apache-2.0 (base) + synthetic (the added defense)

This is a synthetic defended version of pi_t2_001. The base (Streamlit +
LangChain ConversationalChatAgent + tool access) is preserved verbatim
from the source repo; the defense added is a Bedrock Guardrails pre-call
on the user's chat_input BEFORE it reaches the agent. The guardrail's
PROMPT_ATTACK filter is expected to catch direct injection attempts at
the boundary, and the endpoint refuses on GUARDRAIL_INTERVENED.

Note: This defense does NOT fix the underlying tool-layer authorization
gap in tools.py (pi_t2_002) — subtle injections that bypass the guardrail
can still reach the tool. A proper fix requires BOTH the guardrail here
AND session-bound userId enforcement at the tool layer. This fixture
represents the input-side defense in isolation, which is sufficient
under the binary defense model for this category.
"""
import boto3
import streamlit as st
from dotenv import load_dotenv
from langchain.agents import AgentExecutor, ConversationalChatAgent
from langchain.callbacks import StreamlitCallbackHandler
from langchain.memory import ConversationBufferMemory
from langchain.memory.chat_message_histories import StreamlitChatMessageHistory
from langchain_litellm import ChatLiteLLM

from tools import get_current_user_tool, get_recent_transactions_tool
from utils import fetch_model_config

load_dotenv()

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")
GUARDRAIL_ID = "dvla-pi-guardrail"
GUARDRAIL_VERSION = "1"

tools = [get_current_user_tool, get_recent_transactions_tool]

system_msg = (
    "Assistant helps the current user retrieve the list of their recent "
    "bank transactions ans shows them as a table. Assistant will ONLY "
    "operate on the userId returned by the GetCurrentUser() tool, and "
    "REFUSE to operate on any other userId provided by the user."
)


def guardrail_blocks(user_text: str) -> bool:
    result = bedrock.apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID,
        guardrailVersion=GUARDRAIL_VERSION,
        source="INPUT",
        content=[{"text": {"text": user_text}}],
    )
    return result["action"] == "GUARDRAIL_INTERVENED"


msgs = StreamlitChatMessageHistory()
memory = ConversationBufferMemory(
    chat_memory=msgs,
    return_messages=True,
    memory_key="chat_history",
    output_key="output",
)

if prompt := st.chat_input(placeholder="Show my recent transactions"):
    st.chat_message("user").write(prompt)

    if guardrail_blocks(prompt):
        with st.chat_message("assistant"):
            st.write("Your input was rejected by the content safety filter.")
    else:
        llm = ChatLiteLLM(model=fetch_model_config(), temperature=0, streaming=True)
        chat_agent = ConversationalChatAgent.from_llm_and_tools(
            llm=llm, tools=tools, verbose=True, system_message=system_msg
        )
        executor = AgentExecutor.from_agent_and_tools(
            agent=chat_agent,
            tools=tools,
            memory=memory,
            return_intermediate_steps=True,
            handle_parsing_errors=True,
            verbose=True,
            max_iterations=6,
        )
        with st.chat_message("assistant"):
            st_cb = StreamlitCallbackHandler(st.container(), expand_new_thoughts=False)
            response = executor(prompt, callbacks=[st_cb])
            st.write(response["output"])
