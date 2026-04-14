"""Synthetic fixture: stored prompt injection via DB-backed user profile.

The classic 'render user-supplied profile field into a prompt months later'
attack. An attacker fills their bio with a prompt-injection payload and
waits. When ANY operation that renders that user's bio into a prompt fires
(welcome email generation, intro paragraph, summary), the payload executes
in someone else's session — typically an admin or recommendation engine.
"""
from anthropic import Anthropic
from sqlalchemy import create_engine, text

client = Anthropic(api_key="REDACTED")
engine = create_engine("postgresql://localhost/app")


def generate_intro(user_id: int) -> str:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name, bio FROM users WHERE id = :id"),
            {"id": user_id},
        ).fetchone()
    name, bio = row
    system_prompt = (
        f"You are writing a friendly intro for {name}. "
        f"Their self-description is: {bio}"
    )
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=512,
        system=system_prompt,
        messages=[{"role": "user", "content": "Write the intro now."}],
    )
    return response.content[0].text
