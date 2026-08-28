import os
import uuid
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from ocr_engine import process_screenshot
from detector import check_synthetic_image, analyze_content

app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

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
    has_image = False

    if image_file and image_file.filename != '':
        if allowed_file(image_file.filename):
            has_image = True
            ext = image_file.filename.rsplit('.', 1)[1].lower()
            unique_name = f"{uuid.uuid4().hex}.{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            image_file.save(file_path)

            try:
                ocr_result = process_screenshot(file_path)
                ocr_extracted_text = ocr_result.get('text', '')
                domain_inspections = ocr_result.get('urls', [])
                synthetic_result = check_synthetic_image(file_path)
            finally:
                if os.path.exists(file_path):
                    os.remove(file_path)
        else:
            return jsonify({
                "status": "error",
                "message": "Unsupported file format. Please upload PNG, JPG, JPEG, or WEBP."
            }), 400

    combined_text = f"{raw_text} {ocr_extracted_text}".strip()

    # Allow processing if either text was provided, OCR succeeded, OR an image was uploaded
    if not combined_text and not has_image:
        return jsonify({
            "status": "error",
            "message": "Please provide a text message or a valid screenshot to analyze."
        }), 400

    # Run detection pipeline
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
    app.run(host='0.0.0.0', port=5000, debug=True)
