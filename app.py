import os
import uuid
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from ocr_engine import process_screenshot
from detector import check_synthetic_image, analyze_content

app = Flask(__name__)

# Configure upload directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    raw_text = request.form.get('text', '').strip()
    image_file = request.files.get('image')

    ocr_extracted_text = ""
    domain_inspections = []
    synthetic_result = {"is_synthetic": False, "confidence": 0}

    # Handle image upload / clipboard paste screenshot
    if image_file and image_file.filename != '':
        if allowed_file(image_file.filename):
            # Save file with unique name to prevent collisions
            ext = image_file.filename.rsplit('.', 1)[1].lower()
            unique_name = f"{uuid.uuid4().hex}.{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            image_file.save(file_path)

            try:
                # 1. Optical Link Extraction & OCR
                ocr_result = process_screenshot(file_path)
                ocr_extracted_text = ocr_result.get('text', '')
                domain_inspections = ocr_result.get('urls', [])

                # 2. Synthetic Screenshot Detection
                synthetic_result = check_synthetic_image(file_path)
            finally:
                # Clean up uploaded file from server storage
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            return jsonify({
                "status": "error",
                "message": "Unsupported file format. Please upload a PNG, JPG, JPEG, or WEBP image."
            }), 400

    # Combine user-provided text with OCR scanned text
    combined_text = f"{raw_text} {ocr_extracted_text}".strip()

    if not combined_text and not domain_inspections and not synthetic_result["is_synthetic"]:
        return jsonify({
            "status": "error",
            "message": "No valid text or readable screenshot content was provided for analysis."
        }), 400

    # 3. Explainable AI (XAI) Risk & Phishing Reasoning
    analysis = analyze_content(
        raw_text=combined_text,
        domain_inspections=domain_inspections,
        is_synthetic=synthetic_result.get("is_synthetic", False)
    )

    return jsonify({
        "status": "success",
        "combined_text": combined_text,
        "ocr_text": ocr_extracted_text,
        "domain_inspections": domain_inspections,
        "synthetic_detection": synthetic_result,
        "analysis": analysis
    })


if __name__ == '__main__':
    # Run development server
    app.run(host='127.0.0.1', port=5000, debug=True)