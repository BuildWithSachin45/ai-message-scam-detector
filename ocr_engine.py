import re
from urllib.parse import urlparse
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract

def preprocess_image(image_path):
    """
    Applies lightweight Pillow filters (grayscale, contrast boost, sharpening)
    to maximize OCR character recognition accuracy.
    """
    img = Image.open(image_path).convert('L')
    # Boost contrast for clear text edges
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.8)
    # Slight sharpening filter
    img = img.filter(ImageFilter.SHARPEN)
    return img

def extract_urls(text):
    """
    Detects embedded URLs, domains, and raw IP addresses using regex.
    """
    # Regex to capture http/https links, www domains, and IPv4 addresses with optional ports
    url_pattern = r'((?:https?://|www\.)[^\s/$.?#].[^\s]*|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?)'
    matches = re.findall(url_pattern, text)
    
    clean_urls = []
    for match in matches:
        # Strip all surrounding brackets, quotes, and trailing punctuation captured by OCR
        cleaned = match.strip().strip("[](){}<>'\"`").rstrip(".,;:)'\"")
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls

def inspect_domain_security(url_list):
    """
    Inspects extracted links for common phishing/fraud indicators:
    - Raw IP addresses used as hosts
    - Missing HTTPS / SSL encryption
    - Suspicious keywords in the URL path or domain
    """
    inspections = []
    suspicious_keywords = ['verify', 'login', 'secure', 'update', 'kyc', 'bank', 'upi', 'claim', 'bonus', 'free']
    
    for url in url_list:
        # Clean potential bracket noise that causes ValueError: Invalid IPv6 URL
        sanitized_url = url.strip().strip("[](){}<>'\"`").rstrip(".,;:)'\"")
        if not sanitized_url:
            continue

        parse_target = sanitized_url if sanitized_url.startswith(('http://', 'https://')) else f'http://{sanitized_url}'
        
        try:
            parsed = urlparse(parse_target)
            hostname = parsed.hostname or parsed.netloc or ''
            # Remove port numbers or residual characters from hostname
            hostname = hostname.split(':')[0].strip('[]')
        except ValueError:
            # Skip invalid URL strings that fail URL standard parsing
            continue
        
        # Check if the hostname is a direct IPv4 address
        is_ip = bool(re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', hostname))
        
        # Check protocol
        is_insecure_http = sanitized_url.startswith('http://')
        
        # Check suspicious keyword spoofing
        has_phish_words = any(word in sanitized_url.lower() for word in suspicious_keywords)
        
        inspections.append({
            'url': sanitized_url,
            'hostname': hostname,
            'is_ip': is_ip,
            'is_insecure_http': is_insecure_http,
            'has_phish_words': has_phish_words
        })
        
    return inspections

def process_screenshot(image_path):
    """
    Main pipeline to extract text and analyze extracted links from an image.
    """
    try:
        processed_img = preprocess_image(image_path)
        extracted_text = pytesseract.image_to_string(processed_img)
    except Exception as e:
        extracted_text = ""
        print(f"[OCR Error] Tesseract processing failed: {e}")

    extracted_urls = extract_urls(extracted_text)
    domain_report = inspect_domain_security(extracted_urls)

    return {
        "text": extracted_text.strip(),
        "urls": domain_report
    }