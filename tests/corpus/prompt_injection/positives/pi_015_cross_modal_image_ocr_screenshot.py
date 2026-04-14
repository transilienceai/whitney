"""Synthetic fixture: prompt injection via OCR'd image content.

An app accepts an uploaded screenshot, OCRs it with Tesseract, and
feeds the extracted text to an LLM for summarization. An attacker
uploads an image containing injection text — possibly hidden as a
watermark, low-contrast overlay, or steganographic pattern — that
OCR extracts and the LLM follows.
"""
import pytesseract
from flask import Flask, request
from openai import OpenAI
from PIL import Image

app = Flask(__name__)
client = OpenAI(api_key="REDACTED")


@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot():
    image = Image.open(request.files["screenshot"].stream)
    ocr_text = pytesseract.image_to_string(image)
    prompt = (
        "Summarize the content visible in this screenshot in one "
        f"paragraph:\n\n{ocr_text}"
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
