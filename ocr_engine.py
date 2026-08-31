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
    Normalizes common OCR character misreads (e.g. 0TP -> OTP, p1n -> pin, l1nk -> link).
    """
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
    """
    Extracts all HTTP/HTTPS links, bare domains, and IP endpoints from raw/OCR text.
    """
    if not text:
        return []
    url_pattern = r'((?:https?://|www\.)[^\s/$.?#].[^\s]*|[a-zA-Z0-9-]+\.(?:com|org|net|in|co|info|biz|xyz|top|site|live|click|app|online|cc|pw|icu|rest|club|link|vip|store)(?:/[^\s]*)?|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?(?:/[^\s]*)?)'
    matches = re.findall(url_pattern, text, flags=re.IGNORECASE)
    clean_urls = []
    for match in matches:
        cleaned = re.sub(r'[.,;:)\'\"\s>]+$', '', match)
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls


def inspect_domain_security(url_list):
    """
    Deep heuristic inspection of URL structure, brand-squatting, protocol safety, and TLDs.
    """
    inspections = []
    suspicious_auth_keywords = ['verify', 'login', 'secure', 'update', 'kyc', 'bank', 'upi', 'claim', 'bonus', 'free', 'sbi', 'portal', 'reward', 'refund', 'pan', 'aadhaar']
    suspicious_tlds = ['.xyz', '.top', '.click', '.site', '.live', '.online', '.cc', '.pw', '.icu', '.rest', '.club', '.link', '.vip', '.work']
    trusted_domains = ['amazon.in', 'amazon.com', 'sbi.co.in', 'onlinesbi.sbi', 'netflix.com', 'cybercrime.gov.in', 'gov.in', 'nic.in']

    for url in url_list:
        parse_target = url if (url.startswith('http://') or url.startswith('https://')) else f'http://{url}'
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or parsed.netloc or '').lower()
        
        is_ip = bool(re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', hostname))
        is_insecure_http = url.lower().startswith('http://') and not is_ip
        has_phish_words = any(word in url.lower() for word in suspicious_auth_keywords)
        has_suspicious_tld = any(hostname.endswith(tld) for tld in suspicious_tlds)
        
        # Detect brand impersonation (e.g., "sbi-secure-login.example.com")
        impersonated_brand = None
        for brand in ['sbi', 'amazon', 'netflix', 'paytm', 'phonepe', 'hdfc', 'icici', 'axis']:
            if brand in hostname and not any(hostname.endswith(td) for td in trusted_domains):
                impersonated_brand = brand.upper()
                break

        inspections.append({
            'url': url,
            'hostname': hostname,
            'is_ip': is_ip,
            'is_insecure_http': is_insecure_http,
            'has_phish_words': has_phish_words,
            'has_suspicious_tld': has_suspicious_tld,
            'impersonated_brand': impersonated_brand
        })
    return inspections


def process_screenshot(image_path):
    """
    Memory-efficient, multi-mode OCR extraction with contrast enhancement.
    """
    extracted_text = ""
    try:
        with Image.open(image_path) as raw_img:
            raw_img.thumbnail((1200, 1200), Image.Resampling.LANCZOS)
            img_gray = raw_img.convert('L')
            
            # Dark mode detection
            stat = ImageStat.Stat(img_gray)
            if stat.mean[0] < 115:
                img_gray = ImageOps.invert(img_gray)
                
            enhancer = ImageEnhance.Contrast(img_gray)
            enhanced = enhancer.enhance(1.8).filter(ImageFilter.SHARPEN)
            
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
