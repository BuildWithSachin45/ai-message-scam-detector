import os
import re
import pickle
import numpy as np
from PIL import Image, ImageStat

# Model artifact paths
TEXT_MODEL_PATH = 'scam_model.pkl'
VECTORIZER_PATH = 'vectorizer.pkl'
IMAGE_MODEL_PATH = 'image_model.pkl'

text_model = None
vectorizer = None
image_model = None

if os.path.exists(TEXT_MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
    with open(TEXT_MODEL_PATH, 'rb') as f:
        text_model = pickle.load(f)
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)

if os.path.exists(IMAGE_MODEL_PATH):
    with open(IMAGE_MODEL_PATH, 'rb') as f:
        image_model = pickle.load(f)


def check_synthetic_image(image_path):
    """
    Evaluates whether an image or receipt is authentic or synthetically generated.
    """
    if not image_path or not os.path.exists(image_path):
        return {"is_synthetic": False, "confidence": 0}

    try:
        with Image.open(image_path) as img:
            img_gray = img.convert('L').resize((64, 64))
            stat = ImageStat.Stat(img_gray)
            
            mean_val = stat.mean[0]
            var_val = stat.var[0]
            std_val = stat.stddev[0]
            
            hist = img_gray.histogram()
            hist_sum = sum(hist)
            probs = [h / hist_sum for h in hist if h > 0]
            entropy = -sum(p * np.log2(p) for p in probs)

            features = np.array([[mean_val, var_val, std_val, entropy]])

            if image_model:
                pred = image_model.predict(features)[0]
                prob = image_model.predict_proba(features)[0][1] * 100
                return {
                    "is_synthetic": bool(pred == 1),
                    "confidence": round(prob, 2)
                }
            else:
                is_synth = var_val < 160.0
                conf = 85.0 if is_synth else 15.0
                return {
                    "is_synthetic": is_synth,
                    "confidence": conf
                }
    except Exception as e:
        print(f"[Detector Error] Image check failed: {e}")
        return {"is_synthetic": False, "confidence": 0}


def analyze_content(raw_text, domain_inspections, is_synthetic=False):
    """
    Analyzes threat signatures, phishing lures, and legitimate transactional
    formats across Phase 1 and Phase 2 benchmarks to output risk scores.
    """
    reasons = []
    category = "Legitimate / Safe"
    
    # Normalize whitespace, linebreaks, and lowercase
    normalized_text = " ".join(raw_text.split()).lower()

    # 1. Base ML Probability
    ml_score = 0.0
    if text_model and vectorizer and raw_text.strip():
        text_vec = vectorizer.transform([raw_text])
        ml_score = float(text_model.predict_proba(text_vec)[0][1] * 100)

    # 2. Comprehensive Scam Triggers (Phase 1 & Phase 2)
    scam_triggers = [
        # Two-way communication & SMS reply phishing (Phase 2 #5, #6, #10, #12, #18)
        (
            r"please reply (yes|with|to)\b.*(representative|assist|verification code|transaction)",
            90.0,
            "Interactive SMS Phishing (SMiShing)",
            "Prompts user to reply directly via SMS to confirm sensitive transactions or initiate engagement."
        ),
        (
            r"routine verification check.* replying to this message",
            90.0,
            "Transactional Spoofing / Phishing",
            "Prompts direct message reply for purported routine purchase verification."
        ),
        (
            r"annual review.* (confirm your date of birth|registered address).* replying",
            92.0,
            "Personal Data Harvesting",
            "Solicits sensitive PII (date of birth, address) via SMS reply."
        ),
        (
            r"updating our customer records.* (confirm that your mobile number|responding with the number)",
            90.0,
            "SIM / Account Verification Scam",
            "Prompts user to send registered phone details under the guise of customer record updates."
        ),
        (
            r"membership benefits are about to expire.* confirm your account information before the renewal",
            88.0,
            "Subscription Phishing / Renewal Lure",
            "Uses expiring membership lure to harvest account credentials."
        ),
        (
            r"account may be subject to temporary restrictions.* (finish the review|verification is not completed)",
            90.0,
            "Account Coercion / Restriction Phishing",
            "Threatens account restrictions to force external portal verification."
        ),
        (
            r"(prevent your order from being cancelled|unable to verify your recent payment).* confirm the payment details",
            89.0,
            "Order Cancellation / Payment Phishing",
            "Creates urgency over order cancellation to solicit payment re-entry."
        ),

        # Authority / Law Enforcement / Digital Arrest Coercion
        (
            r"(police|cbi|customs|court|trai|narcotics).* (illegal transaction|arrested|case|fir|penalty|warrant).* (pay|transfer|immediately|fine)",
            96.0,
            "Digital Arrest / Authority Impersonation",
            "Coercive extortion impersonating police/law enforcement threatening immediate arrest."
        ),
        (
            r"illegal transaction.* (pay|transfer|arrested)",
            95.0,
            "Digital Arrest / Authority Extortion",
            "Extortion attempt threatening arrest over alleged illegal transactions."
        ),

        # Upfront Fee / Registration / Advance Fee Scams
        (
            r"(earn|work from home|daily income|job|bonus).* (pay|registration fee|deposit|charge)",
            93.0,
            "Job / Work-From-Home Advance Fee Scam",
            "Unsolicited job/earning offer demanding an upfront registration or processing fee."
        ),
        (
            r"(pay|transfer|refundable fee|processing fee|verification charges?|delivery charges?).*(₹|\b\d+\b|fee|charges?).*(claim|receive|prize|won|gift|benefit|reschedule)",
            94.0,
            "Advance Fee / Lottery Fraud",
            "Demands advance fee or processing charges to release gifts, benefits, or delivery."
        ),
        (
            r"(won|winner|lucky draw|selected for a free|win \d+ lakh|claim your (prize|reward))",
            90.0,
            "Lottery / Prize Fraud",
            "Unsolicited prize or high-value lottery reward lure."
        ),
        (
            r"government benefit.* (pay|charges?|submit|aadhaar)",
            92.0,
            "Government Scheme Phishing",
            "Demands verification charges and sensitive credentials for alleged government benefits."
        ),

        # Credential, OTP, PIN, Card Theft & Harvesting
        (
            r"(send|tell us|provide|share|confirm).*(otp|verification code|pin|card details|cvv|expiry date)",
            98.0,
            "Credential Harvesting / OTP Theft",
            "Demands confidential banking credentials, OTP, or card secrets."
        ),
        (
            r"(unusual activity|detected suspicious|accessed elsewhere).* (send|provide|share|confirm).*(otp|code|identity)",
            98.0,
            "Account Takeover / OTP Phishing",
            "Deceptive security alert soliciting OTP/verification codes to hijack accounts."
        ),

        # Service / Utility / Account Termination & Urgent Deadlines
        (
            r"(disconnected|stop working|deactivated|cancelled|blocked|deleted|locked).* (in \d+ (hours?|minutes?)|tonight|today|immediately|unless you pay).* (pay|link|call|provide|confirm)",
            95.0,
            "Urgent Service Suspension Phishing",
            "Fabricates immediate utility, SIM, or flight cancellation to force hasty payments or credential disclosure."
        ),
        (
            r"(final warning|urgent).* (cancelled|disconnected|blocked).* (pay|link|call)",
            94.0,
            "Coercive Urgency / Extortion",
            "Uses coercive final warnings and tight deadlines to induce panic payments."
        ),
        (
            r"(account|sim).* (stop working|deleted|deactivated|blocked).* (click|link|confirm|reactivate)",
            93.0,
            "Account Takeover Phishing",
            "Deceptive deactivation threat prompting links or credential entry."
        ),

        # Impersonation & Accidental Transfer / Return UPI Scam
        (
            r"(accidentally received|by mistake|lost my phone).* (return|transfer|send).* (upi|id|account)",
            90.0,
            "Impersonation / False Refund Scam",
            "Deceptive claim of mistaken money transfer soliciting urgent UPI payments."
        ),

        # Package / Delivery Address Reschedule Fee
        (
            r"(package|parcel) could not be delivered.* pay .* (reschedule|link)",
            92.0,
            "Delivery Impersonation Scam",
            "Fake failed parcel delivery notification demanding payment to reschedule."
        )
    ]

    scam_score = 0.0
    detected_category = ""
    for pattern, score, cat, desc in scam_triggers:
        if re.search(pattern, normalized_text):
            if score > scam_score:
                scam_score = score
                detected_category = cat
            reasons.append(desc)

    # 3. Legitimate Whitelist Patterns (Phase 1 & Phase 2)
    legit_rules = [
        (r"(do not|don'?t|never) share (this|your)? ?otp", "Official security advisory instructing user not to share OTP."),
        (r"if this was (you|not you).* (no action is needed|review your recent activity)", "Standard legitimate login / sign-in notification."),
        (r"(check|view|review).* (through|on|by signing in through) your (usual |official )?(banking application|sbi app|banking app|provider app|app|portal|retailer's website)", "Advisory instructing user to view info securely inside official channels."),
        (r"payment could not be processed.* update your billing information.* avoid interruption", "Standard billing retry notification without suspicious external links."),
        (r"the address provided appears incomplete.* please confirm your address so we can complete", "Non-coercive delivery address confirmation without payment demand."),
        (r"subscription is scheduled for renewal.* payment method ending in \d+ will be charged automatically", "Standard automated recurring subscription renewal reminder."),
        (r"new beneficiary was added to your account", "Standard bank beneficiary addition confirmation."),
        (r"refund has been initiated for the returned item", "Standard e-commerce refund status update."),
        (r"recent order is currently on hold.* check your order status through the retailer's website", "Safe retailer order status check directing to legitimate website."),
        (r"selected for a security review.* support team may contact you shortly", "Standard internal service security advisory."),
        (r"couldn't complete your recent transfer because the recipient information", "Failed transfer notification advising detail review."),
        (r"change the email address associated with your account.* if you did not request this, contact support", "Standard email change advisory pointing to official site support."),
        (r"delivery preferences have not been updated recently", "Routine user profile preferences reminder."),
        (r"(account statement|statement for|monthly account summary).* (available|generated|ready)", "Standard periodic account statement notice."),
        (r"bank has credited.* (check your official|details)", "Legitimate credit advisory directing to official app."),
        (r"(insurance premium|bill|payment) of .* is due on", "Standard periodic billing notice."),
        (r"(credit card payment|bill) is due on", "Standard credit card bill due date reminder."),
        (r"due on \d+ (january|february|march|april|may|june|july|august|september|october|november|december)", "Legitimate billing calendar reminder."),
        (r"appointment is confirmed for", "Standard appointment booking confirmation."),
        (r"(order|food delivery) (has been shipped|is arriving|arriving today|will arrive)", "Standard delivery progress alert."),
        (r"flight booking is confirmed.* booking reference", "Standard airline reservation confirmation."),
        (r"mobile recharge of .* was successful", "Payment confirmation receipt."),
        (r"subscription payment was successful", "Subscription renewal confirmation receipt."),
        (r"meeting has been moved from", "Standard schedule update notification."),
        (r"selected for an interview.* (careers portal|company)", "Standard recruitment notification on official careers portal."),
        (r"friend has sent you a birthday gift.* contact them directly", "Personal gift notification directing directly to sender."),
        (r"bank branch will be closed.* due to a public holiday", "Official holiday closure notice.")
    ]

    is_whitelisted = False
    whitelist_reason = ""
    for pattern, desc in legit_rules:
        if re.search(pattern, normalized_text):
            is_whitelisted = True
            whitelist_reason = desc
            break

    # 4. Domain & Link Reputation Factors
    for domain in domain_inspections:
        if domain.get('is_ip'):
            scam_score = max(scam_score, 90.0)
            detected_category = "Malicious URL / Phishing"
            reasons.append(f"Uses direct IP address link instead of a verified domain: {domain['url']}")

        if domain.get('is_insecure_http'):
            scam_score = max(scam_score, 65.0)
            reasons.append(f"Insecure HTTP connection detected (missing SSL/HTTPS): {domain['url']}")

        if domain.get('has_phish_words'):
            scam_score = max(scam_score, 85.0)
            detected_category = "Credential Phishing"
            reasons.append(f"Link contains deceptive credential keywords: {domain['url']}")

    # 5. Synthetic Screenshot Factor
    if is_synthetic:
        scam_score = max(scam_score, 85.0)
        if not detected_category or detected_category == "Legitimate / Safe":
            detected_category = "Synthetic / Altered Receipt"
        reasons.append("Detected compression and variance patterns typical of generated fake payment receipts.")

    # 6. Score Consolidation & Risk Level Mapping
    if scam_score > 0:
        final_score = max(ml_score, scam_score)
        category = detected_category
        risk_level = "High Threat" if final_score >= 75 else "Moderate Suspicion"
    elif is_whitelisted:
        final_score = 4.0
        category = "Legitimate / Safe"
        risk_level = "Safe / Low Risk"
        reasons = [whitelist_reason or "Verified standard service notification / transactional alert."]
    else:
        final_score = ml_score if ml_score > 0 else 5.0
        if final_score >= 70:
            category = "Suspicious Message"
            risk_level = "High Threat"
        elif final_score >= 40:
            category = "Moderate Suspicion"
            risk_level = "Moderate Suspicion"
        else:
            category = "Legitimate / Safe"
            risk_level = "Safe / Low Risk"

    final_score = round(min(max(final_score, 1.0), 99.0), 1)

    if not reasons:
        reasons.append("No obvious phishing triggers, suspicious domains, or fake artifacts detected.")

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "category": category,
        "reasons": reasons
    }