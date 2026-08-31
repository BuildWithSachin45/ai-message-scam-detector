import os
import uuid
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from ocr_engine import process_screenshot, extract_urls, inspect_domain_security
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
    all_domain_inspections = []
    synthetic_result = {"is_synthetic": False, "confidence": 0}
    has_image = False

    # 1. Analyze URLs from Pasted Text
    if raw_text:
        text_urls = extract_urls(raw_text)
        text_domain_reports = inspect_domain_security(text_urls)
        all_domain_inspections.extend(text_domain_reports)

    # 2. Analyze Screenshot (OCR + Image URLs + Synthetic Artifacts)
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
                img_domains = ocr_result.get('urls', [])
                
                # Merge domains avoiding duplicates
                existing_urls = {d['url'] for d in all_domain_inspections}
                for d in img_domains:
                    if d['url'] not in existing_urls:
                        all_domain_inspections.append(d)
                        existing_urls.add(d['url'])

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

    if not combined_text and not has_image:
        return jsonify({
            "status": "error",
            "message": "Please enter message text or upload a screenshot to analyze."
        }), 400

    # 3. Multi-Modal Risk Analysis
    analysis = analyze_content(
        raw_text=combined_text,
        domain_inspections=all_domain_inspections,
        is_synthetic=synthetic_result.get("is_synthetic", False)
    )

    return jsonify({
        "status": "success",
        "combined_text": combined_text,
        "ocr_text": ocr_extracted_text,
        "domain_inspections": all_domain_inspections,
        "synthetic_detection": synthetic_result,
        "analysis": analysis
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
