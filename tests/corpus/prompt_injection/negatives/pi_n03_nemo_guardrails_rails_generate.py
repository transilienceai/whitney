"""Synthetic fixture: prompt injection defended by NeMo Guardrails.

NeMo Guardrails (from NVIDIA) wraps the LLM call in a configurable set
of input/output rails. When rails.generate() is called, the input rails
run first; if any rail raises a block, the generation is rejected. The
canonical defense pattern for NeMo is simply to use rails.generate()
instead of calling the raw LLM, with a config that includes an input
rail for prompt injection detection.
"""
from flask import Flask, request
from nemoguardrails import LLMRails, RailsConfig

app = Flask(__name__)

# Config directory contains rails.yaml with:
#   rails:
#     input:
#       flows:
#         - check_jailbreak
#         - check_prompt_injection
config = RailsConfig.from_path("./nemo_config")
rails = LLMRails(config)


@app.route("/summarize", methods=["POST"])
def summarize():
    user_text = request.json["text"]
    # rails.generate applies the configured input rails BEFORE the
    # main LLM call. If any input rail blocks, the response is a
    # rail-rejection message rather than the model's completion.
    result = rails.generate(
        messages=[
            {
                "role": "user",
                "content": f"Summarize the following article: {user_text}",
            }
        ]
    )
    return result["content"]
