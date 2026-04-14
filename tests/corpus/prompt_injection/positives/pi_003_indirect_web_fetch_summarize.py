"""Synthetic fixture: indirect prompt injection via web fetch result.

The 'summarize this URL' pattern. requests.get(url).text fetches arbitrary
attacker-controlled content (the URL might be benign-looking, the page
behind it is not). The fetched HTML/text is interpolated into the prompt
with no separation between instructions and data.
"""
import requests
from anthropic import Anthropic

client = Anthropic(api_key="REDACTED")


def fetch_and_summarize(url: str) -> str:
    page_text = requests.get(url, timeout=10).text
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": f"Summarize the contents of this web page:\n\n{page_text}",
            }
        ],
    )
    return response.content[0].text
