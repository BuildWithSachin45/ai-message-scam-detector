import re
import os
import shutil
from urllib.parse import urlparse
from PIL import Image, ImageOps, ImageEnhance, ImageFilter, ImageStat
import pytesseract

# Auto-detect Tesseract binary path
if shutil.which("tesseract"):
    pytesseract.pytesseract.tesseract_cmd = shutil.which("tesseract")
elif os.path.exists("/usr/bin/tesseract"):
    pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"
elif os.path.exists(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


def clean_ocr_typos(text):
    """
    Normalizes common OCR character misreads (0TP -> OTP, p1n -> pin, l1nk -> link).
    """
    if not text:
        return ""
    cleaned = text
    typo_subs = [
        (r'\b0tp\b', 'otp'),
        (r'\b0TP\b', 'OTP'),
        (r'\bp1n\b', 'pin'),
        (r'\bl1nk\b', 'link'),
        (r'\bcl1ck\b', 'click'),
        (r'b1ock(ed)?', r'block\1'),
        (r'up[i!l1]\b', 'upi'),
        (r'[\u20b9]', '₹')
    ]
    for pattern, replacement in typo_subs:
        cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
    return cleaned


def preprocess_screenshot(img_path):
    """
    Generates optimized image variants for OCR:
    - Automatically handles dark mode by inverting dark backgrounds
    - Upscales small screenshots for sharper character boundaries
    """
    with Image.open(img_path) as raw_img:
        # Convert to RGB then Grayscale
        img = raw_img.convert('L')
        
        # Check average brightness to detect Dark Mode
        stat = ImageStat.Stat(img)
        avg_brightness = stat.mean[0]
        
        if avg_brightness < 120:  # Dark Mode screenshot
            img = ImageOps.invert(img)
            
        # Upscale if low resolution
        w, h = img.size
        if w < 1000 or h < 1000:
            img = img.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
            
        # Enhance contrast and sharpen
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
    suspicious_keywords = ['verify', 'login', 'secure', 'update', 'kyc', 'bank', 'upi', 'claim', 'bonus', 'free', 'sbi']
    
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
        processed_img = preprocess_screenshot(image_path)
        # Run OCR with sparse text engine mode (--psm 11 + --psm 6)
        text_pass1 = pytesseract.image_to_string(processed_img, config='--oem 3 --psm 6')
        text_pass2 = pytesseract.image_to_string(processed_img, config='--oem 3 --psm 11')
        
        # Combine unique lines from both passes
        combined = f"{text_pass1}\n{text_pass2}"
        extracted_text = clean_ocr_typos(combined)
    except Exception as e:
        print(f"[OCR Warning] Image OCR failed: {e}")

    extracted_urls = extract_urls(extracted_text)
    domain_report = inspect_domain_security(extracted_urls)

    return {
        "text": extracted_text.strip(),
        "urls": domain_report
    }
