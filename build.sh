#!/usr/bin/env bash
set -o errexit

# Update and install tesseract on debian-based linux instances
if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y tesseract-ocr || true
fi

pip install --upgrade pip
pip install -r requirements.txt
