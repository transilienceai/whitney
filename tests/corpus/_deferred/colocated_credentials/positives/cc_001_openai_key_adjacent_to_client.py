"""Synthetic fixture: hardcoded OpenAI API key co-located with SDK call."""
from openai import OpenAI

OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH"

client = OpenAI(api_key=OPENAI_API_KEY)


def chat(user_message: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_message}],
    )
    return response.choices[0].message.content
