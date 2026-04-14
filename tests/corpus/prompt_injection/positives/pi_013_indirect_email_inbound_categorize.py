"""Synthetic fixture: prompt injection via inbound email body.

SES delivers inbound email via SNS → HTTPS POST to this endpoint. The
email body is fed to an LLM for categorization (urgent/normal/spam).
A spammer sends an email with a prompt-injection payload; the model
follows the injection and categorizes the attacker's email as "urgent"
regardless of its actual content, bypassing the spam filter.
"""
from anthropic import Anthropic
from flask import Flask, request

app = Flask(__name__)
client = Anthropic(api_key="REDACTED")


@app.route("/ses-inbound", methods=["POST"])
def process_inbound():
    payload = request.json
    record = payload["Records"][0]["ses"]
    email_body = record["mail"]["content"]
    sender = record["mail"]["source"]
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=512,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Categorize this email from {sender} as urgent, normal, or spam. "
                    f"Return only the category word.\n\n{email_body}"
                ),
            }
        ],
    )
    category = response.content[0].text.strip().lower()
    if category == "urgent":
        notify_oncall(sender, email_body)
    elif category == "spam":
        pass
    else:
        forward_to_inbox(sender, email_body)
    return "", 200


def notify_oncall(sender: str, body: str) -> None:
    pass


def forward_to_inbox(sender: str, body: str) -> None:
    pass
