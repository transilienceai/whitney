"""Synthetic fixture: prompt injection via Click CLI + stdin.

A `summarize` CLI that reads document text from stdin and asks
Anthropic to summarize it. The stdin channel is attacker-influenced
when the CLI is invoked in a pipeline like
  cat /var/log/uploaded_reports/*.txt | summarize
where the attacker controls the uploaded_reports contents.
"""
import sys

import click
from anthropic import Anthropic

client = Anthropic(api_key="REDACTED")


@click.command()
@click.option("--prompt-prefix", default="Summarize the following text: ")
@click.option("--model", default="claude-3-5-sonnet-20241022")
def summarize(prompt_prefix: str, model: str) -> None:
    user_content = sys.stdin.read()
    full_prompt = prompt_prefix + user_content
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": full_prompt}],
    )
    click.echo(response.content[0].text)


if __name__ == "__main__":
    summarize()
