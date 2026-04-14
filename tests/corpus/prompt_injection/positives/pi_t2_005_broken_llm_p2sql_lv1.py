"""Tier 2 fixture: Broken_LLM_Integration_App p2sql_injection_lv1 (verbatim).

Source:  13o-bbr-bbq/Broken_LLM_Integration_App @ 90d3f955
File:    chatapp/backend/app/llm_agent.py
License: MIT

Verbatim function copy. The "lv1" (no-guard) variant of the P2SQL
(prompt-to-SQL) injection endpoint. User input flows into a prompt
template that instructs the LLM to generate SQL, and the generated SQL
is executed against the database via LangChain's SQL chain. Classic
LLM-driven SQL injection: the attacker can make the LLM generate
arbitrary SELECT / INSERT / UPDATE / DELETE against the user-visible
tables (users, chats, memberships, messages, user_settings).

WHY THIS IS IN THE prompt_injection CORPUS (not UOH / llm_output_to_sink):
the ROOT CAUSE is prompt injection at the template-variable level
(the LLM is tricked via the question argument into generating malicious
SQL). The downstream SQL execution is the IMPACT. Primary vuln_subtype
is DPI-5 (template variable prompt injection); the SQL execution is
captured in the reasoning field as an amplifying impact note.
"""
from .llm_db_chain import create_db_chain
from .llm_prompt_templates import p2sql_injection_lv1_template


def p2sql_injection_lv1(question: str) -> str:
    try:
        prompt = p2sql_injection_lv1_template.format(
            top_k=5,
            table_info="users, chats, memberships, messages, user_settings",
            question=question,
        )
        answer = create_db_chain().run(prompt)
        return ",".join(answer) if isinstance(answer, list) else str(answer)
    except Exception as e:
        return f"Error in ask_question_db: {', '.join(map(str, e.args))}"
