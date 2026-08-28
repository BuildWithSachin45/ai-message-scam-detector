FROM python:3.11-slim

# Install system tesseract-ocr binary and language data
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Expose Render port
EXPOSE 5000

# Start production server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
