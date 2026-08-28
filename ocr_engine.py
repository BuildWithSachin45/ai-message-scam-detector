import re
import os
import shutil
from urllib.parse import urlparse
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract

# Auto-detect Tesseract binary path on Linux (Render/Ubuntu) and Windows
if shutil.which("tesseract"):
    pytesseract.pytesseract.tesseract_cmd = shutil.which("tesseract")
elif os.path.exists("/usr/bin/tesseract"):
    pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"
elif os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def preprocess_image(image_path):
    img = Image.open(image_path).convert('L')
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.8)
    img = img.filter(ImageFilter.SHARPEN)
    return img

def extract_urls(text):
    url_pattern = r'((?:https?://|www\.)[^\s/$.?#].[^\s]*|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?)'
    matches = re.findall(url_pattern, text)
    clean_urls = []
    for match in matches:
        cleaned = re.sub(r'[.,;:)\'\"]+$', '', match)
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls

def inspect_domain_security(url_list):
    inspections = []
    suspicious_keywords = ['verify', 'login', 'secure', 'update', 'kyc', 'bank', 'upi', 'claim', 'bonus', 'free']
    
    for url in url_list:
        parse_target = url if (url.startswith('http://') or url.startswith('https://')) else f'http://{url}'
        parsed = urlparse(parse_target)
        hostname = parsed.hostname or parsed.netloc or ''
        is_ip = bool(re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', hostname))
        is_insecure_http = url.startswith('http://')
        has_phish_words = any(word in url.lower() for word in suspicious_keywords)
        
        inspections.append({
            'url': url,
            'hostname': hostname,
            'is_ip': is_ip,
            'is_insecure_http': is_insecure_http,
            'has_phish_words': has_phish_words
        })
    return inspections

def process_screenshot(image_path):
    extracted_text = ""
    try:
        processed_img = preprocess_image(image_path)
        extracted_text = pytesseract.image_to_string(processed_img)
    except Exception as e:
        print(f"[OCR Warning] Image OCR failed (fallback to image scanner): {e}")

    extracted_urls = extract_urls(extracted_text)
    domain_report = inspect_domain_security(extracted_urls)

    return {
        "text": extracted_text.strip(),
        "urls": domain_report
    }
