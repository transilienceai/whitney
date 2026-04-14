"""Synthetic fixture: prompt injection via CLI argparse argument.

A simple command-line assistant that takes a `--question` arg and
sends it to OpenAI. Running on a shared CI/build system or exposed
via a sudo wrapper, the CLI arg becomes an attacker-influenced channel
— e.g., a Git pre-commit hook that runs `llm-helper --question "$(git
log -1 --format=%s)"` reads the commit message as the question, and
a malicious committer can embed injection payloads in commit messages.
"""
import argparse

from openai import OpenAI

client = OpenAI(api_key="REDACTED")


def main() -> None:
    parser = argparse.ArgumentParser(description="CLI LLM assistant")
    parser.add_argument("--question", required=True, help="Question to ask")
    parser.add_argument("--model", default="gpt-4o")
    args = parser.parse_args()

    prompt = f"Answer this question helpfully and concisely: {args.question}"
    response = client.chat.completions.create(
        model=args.model,
        messages=[{"role": "user", "content": prompt}],
    )
    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
