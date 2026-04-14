"""Synthetic fixture: prompt injection via LangChain RedisChatMessageHistory.

A multi-server chatbot uses Redis-backed chat history to preserve
conversation state across servers. The session_id is taken from the
request body (not from the authenticated session cookie), so an
attacker can specify an arbitrary session_id and either read another
user's conversation memory or poison a shared session_id that multiple
users collide on.

The memory replay itself is the prompt injection vector: whatever is in
RedisChatMessageHistory for that session_id gets prepended as
message history on the next LLM call, with no per-retrieval guardrail.
"""
from flask import Flask, request
from langchain_community.chat_message_histories import RedisChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_openai import ChatOpenAI

app = Flask(__name__)
llm = ChatOpenAI(model="gpt-4o", api_key="REDACTED")


def get_history(session_id: str) -> RedisChatMessageHistory:
    return RedisChatMessageHistory(
        session_id=session_id, url="redis://localhost:6379"
    )


chain_with_history = RunnableWithMessageHistory(
    llm,
    get_history,
    input_messages_key="question",
    history_messages_key="history",
)


@app.route("/chat", methods=["POST"])
def chat():
    session_id = request.json.get("session_id", "default")
    question = request.json["question"]
    response = chain_with_history.invoke(
        {"question": question},
        config={"configurable": {"session_id": session_id}},
    )
    return response.content
