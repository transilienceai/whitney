"""Synthetic fixture: prompt injection via Whisper voice transcription.

A voice-question endpoint that accepts an uploaded audio file,
transcribes it via OpenAI Whisper, and feeds the transcript to the
chat completion API. The attacker records audio containing spoken
injection instructions — or crafts an audio file using TTS that
outputs invisible Unicode characters that Whisper transcribes
literally — and the transcribed text flows into the prompt with no
guardrail.
"""
from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/voice-question", methods=["POST"])
def voice_question():
    audio_file = request.files["audio"]
    transcript = client.audio.transcriptions.create(
        model="whisper-1", file=audio_file
    )
    user_question = transcript.text
    prompt = f"Answer the caller's question: {user_question}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
