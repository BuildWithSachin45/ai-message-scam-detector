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
    if not text:
        return ""
    cleaned = text
    subs = [
        (r'\b0tp\b', 'otp'),
        (r'\b0TP\b', 'OTP'),
        (r'\bp1n\b', 'pin'),
        (r'\bP1N\b', 'PIN'),
        (r'\bl1nk\b', 'link'),
        (r'\bcl1ck\b', 'click'),
        (r'b1ock(ed)?', r'block\1'),
        (r'up[i!l1|]\b', 'upi'),
        (r'[\u20b9\?]\s*(\d+)', r'₹\1'),
        (r'\brs\.?\s*(\d+)', r'₹\1')
    ]
    for pattern, replacement in subs:
        cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
    return cleaned


def extract_urls(text):
    url_pattern = r'((?:https?://|www\.)[^\s/$.?#].[^\s]*|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?)'
    matches = re.findall(url_pattern, text)
    clean_urls = []
    for match in matches:
        cleaned = re.sub(r'[.,;:)\'\"\s]+$', '', match)
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls


def inspect_domain_security(url_list):
    inspections = []
    suspicious_keywords = ['verify', 'login', 'secure', 'update', 'kyc', 'bank', 'upi', 'claim', 'bonus', 'free', 'sbi', 'portal']
    
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
        with Image.open(image_path) as raw_img:
            # Downscale large mobile images to fit within safe memory limits (max 1200px)
            raw_img.thumbnail((1200, 1200), Image.Resampling.LANCZOS)
            img_gray = raw_img.convert('L')
            
            # Check for dark mode background
            stat = ImageStat.Stat(img_gray)
            if stat.mean[0] < 115:
                img_gray = ImageOps.invert(img_gray)
                
            # Enhance contrast
            enhancer = ImageEnhance.Contrast(img_gray)
            enhanced = enhancer.enhance(1.8).filter(ImageFilter.SHARPEN)
            
            # Run single optimized OCR pass
            raw_ocr = pytesseract.image_to_string(enhanced, config='--oem 3 --psm 6')
            if not raw_ocr.strip():
                raw_ocr = pytesseract.image_to_string(enhanced, config='--oem 3 --psm 11')
                
            extracted_text = clean_ocr_typos(raw_ocr)
    except Exception as e:
        print(f"[OCR Warning] Image OCR skipped/failed safely: {e}")

    extracted_urls = extract_urls(extracted_text)
    domain_report = inspect_domain_security(extracted_urls)

    return {
        "text": extracted_text.strip(),
        "urls": domain_report
    }
