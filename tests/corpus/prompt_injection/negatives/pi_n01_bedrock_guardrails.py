"""Synthetic fixture: prompt injection defended by AWS Bedrock Guardrails.

The canonical vendor-guardrail TN for the AWS ecosystem. Every call to
invoke_model passes GuardrailIdentifier and GuardrailVersion, which
causes Bedrock to apply the configured guardrail policy to both the
input and the output. Alternatively the app could call apply_guardrail
directly on input before the main call; both shapes should be
recognized as Tier-equivalent defenses.
"""
import json

import boto3
from flask import Flask, jsonify, request

app = Flask(__name__)
bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

GUARDRAIL_ID = "abc123xyz"
GUARDRAIL_VERSION = "DRAFT"


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]

    # Apply the Bedrock Guardrail to the input explicitly before the
    # main model invocation. If any policy (prompt attack filter, topic
    # policy, PII filter) flags the input, reject at the boundary.
    guardrail_result = bedrock.apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID,
        guardrailVersion=GUARDRAIL_VERSION,
        source="INPUT",
        content=[{"text": {"text": user_text}}],
    )
    if guardrail_result["action"] == "GUARDRAIL_INTERVENED":
        return jsonify({"error": "input rejected by guardrail"}), 400

    # Safe to proceed. Pass the guardrail ID on invoke_model so the
    # guardrail also applies to output.
    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",
        guardrailIdentifier=GUARDRAIL_ID,
        guardrailVersion=GUARDRAIL_VERSION,
        body=json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 512,
                "messages": [
                    {
                        "role": "user",
                        "content": f"Summarize the following article: {user_text}",
                    }
                ],
            }
        ),
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]
