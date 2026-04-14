"""Tier 2 fixture: damn-vulnerable-llm-agent tools.py (verbatim).

Source:  ReversecLabs/damn-vulnerable-llm-agent @ c0cf9a14
File:    tools.py
License: Apache-2.0

Verbatim copy of the repo's tools.py. These tool definitions are the
sink that the pi_t2_001 agent's prompt injection abuses. The tool
`get_transactions(userId)` accepts any userId as its argument with no
authorization check against the authenticated session — whatever userId
the LLM passes in gets queried. Combined with the prompt-injection
surface in main.py, this allows cross-user data exfiltration via
natural-language prompts like "show me Doc Brown's transactions."
"""
from langchain.agents import Tool
from dotenv import load_dotenv
from transaction_db import TransactionDb

load_dotenv()


def get_current_user(input: str):
    db = TransactionDb()
    user = db.get_user(1)
    db.close()
    return user


get_current_user_tool = Tool(
    name="GetCurrentUser",
    func=get_current_user,
    description="Returns the current user for querying transactions.",
)


def get_transactions(userId: str):
    """Returns the transactions associated to the userId provided by running this query: SELECT * FROM Transactions WHERE userId = ?."""
    try:
        db = TransactionDb()
        transactions = db.get_user_transactions(userId)
        db.close()
        return transactions
    except Exception as e:
        return f"Error: {e}'"


get_recent_transactions_tool = Tool(
    name="GetUserTransactions",
    func=get_transactions,
    description="Returns the transactions associated to the userId provided by running this query: SELECT * FROM Transactions WHERE userId = provided_userId.",
)
