import re
import os
import shutil
from urllib.parse import urlparse
from PIL import Image, ImageOps, ImageEnhance, ImageFilter, ImageStat
import numpy as np
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
    Cleans up common OCR character substitutions and noise.
    """
    if not text:
        return ""
    
    cleaned = text
    
    # Common OCR character substitutions
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


def preprocess_image_variants(img_path):
    """
    Generates optimized image variants (Standard High-Contrast and Inverted)
    to guarantee text capture across light mode, dark mode, and UI bubbles.
    """
    variants = []
    
    with Image.open(img_path) as raw_img:
        # 1. Convert to RGB then Grayscale
        img_gray = raw_img.convert('L')
        
        # 2. Resize/Upscale for crisp character edges
        w, h = img_gray.size
        scale = 1.0
        if w < 1200 or h < 1200:
            scale = 2.0
            new_size = (int(w * scale), int(h * scale))
            img_gray = img_gray.resize(new_size, Image.Resampling.LANCZOS)
            
        # 3. Standard Enhanced Variant
        enhancer = ImageEnhance.Contrast(img_gray)
        enhanced_img = enhancer.enhance(2.0).filter(ImageFilter.SHARPEN)
        variants.append(enhanced_img)
        
        # 4. Inverted Variant (for Dark Mode / White text on dark bubbles)
        inverted_img = ImageOps.invert(enhanced_img)
        variants.append(inverted_img)
        
    return variants


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
    extracted_texts = []
    
    try:
        variants = preprocess_image_variants(image_path)
        
        for var_img in variants:
            # Run multi-mode PSM passes (PSM 6 for structured blocks, PSM 11 for sparse UI text)
            txt6 = pytesseract.image_to_string(var_img, config='--oem 3 --psm 6')
            txt11 = pytesseract.image_to_string(var_img, config='--oem 3 --psm 11')
            
            if txt6.strip():
                extracted_texts.append(txt6.strip())
            if txt11.strip():
                extracted_texts.append(txt11.strip())
                
    except Exception as e:
        print(f"[OCR Warning] Image OCR pipeline encountered an issue: {e}")

    # Combine all unique lines captured across all passes
    combined_raw = "\n".join(extracted_texts)
    cleaned_final_text = clean_ocr_typos(combined_raw)
    
    # Extract links
    extracted_urls = extract_urls(cleaned_final_text)
    domain_report = inspect_domain_security(extracted_urls)

    return {
        "text": cleaned_final_text.strip(),
        "urls": domain_report
    }
