"""Synthetic fixture: prompt injection via Twilio voice webhook SpeechResult.

Twilio's <Gather input="speech"> element performs speech-to-text
server-side and sends the result to a webhook as form data (the
SpeechResult field). This app's Twilio webhook feeds SpeechResult
directly into an OpenAI prompt and speaks the response back to the
caller via TwiML <Say>. An attacker calls the number and speaks an
injection payload.
"""
from flask import Flask, request
from openai import OpenAI
from twilio.twiml.voice_response import VoiceResponse

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/twilio-voice", methods=["POST"])
def twilio_voice():
    speech_result = request.values.get("SpeechResult", "")
    prompt = f"You are a customer support agent. Respond to the caller who said: {speech_result}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    twiml = VoiceResponse()
    twiml.say(response.choices[0].message.content)
    return str(twiml), 200, {"Content-Type": "application/xml"}
