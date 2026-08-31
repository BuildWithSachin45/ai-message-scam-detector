import os
import re
import pickle
import numpy as np
from PIL import Image, ImageStat

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
    reasons = []
    category = "Legitimate / Safe"
    normalized_text = " ".join(raw_text.split()).lower()

    # 1. Base ML Confidence
    ml_score = 0.0
    if text_model and vectorizer and raw_text.strip():
        text_vec = vectorizer.transform([raw_text])
        ml_score = float(text_model.predict_proba(text_vec)[0][1] * 100)

    # 2. Legitimate Transactional & OTP Whitelist Checks
    legit_rules = [
        # Explicit OTP Delivery & Banking Activation Notifications
        (r"(never|do not|don'?t)\s+(share|disclose|give)\s+(this|your|the)?\s*(otp|pin|password|card|cvv|info)", 
         "Context: Official Security Advisory — Standard transactional guidance warning never to share OTP/PIN."),
        
        (r"(the\s+)?otp\s+to\s+verify\s+.*\s+is\s+\d+", 
         "Context: Legitimate OTP Verification — Standard one-time authentication code dispatch."),
        
        (r"\b\d{4,8}\b\s+is\s+(your\s+)?(otp|verification\s+code|secret\s+code)", 
         "Context: Legitimate OTP Notification — Automated system login/verification code."),
        
        (r"is\s+your\s+otp\s+for\s+.*valid\s+(only\s+)?for\s+\d+\s+minutes", 
         "Context: Standard Timed OTP — Authentic transactional OTP with validity window."),
        
        (r"delivery\s+authentication\s+code\s+.*is\s+\d+", 
         "Context: Delivery Proof PIN — Standard courier/service delivery confirmation code."),
        
        (r"upi\s+activated.*(linked\s+your\s+bank|google\s+pay|phonepe|paytm)", 
         "Context: UPI Registration Confirmation — Routine bank activation alert."),

        # Routine Service Updates & Summaries
        (r"if\s+this\s+was\s+(you|not\s+you).*(no\s+action\s+is\s+needed|review\s+your\s+recent\s+activity)", 
         "Context: Automated Login Advisory — Standard security notification without coercive links."),
        
        (r"(check|view|review).*(through|on|by\s+signing\s+in\s+through)\s+your\s+(usual\s+|official\s+)?(banking\s+application|sbi\s+app|banking\s+app|provider\s+app|app|portal|retailer's\s+website)", 
         "Context: Official In-App Guidance — Advises the user to safely check details inside their registered app."),
        
        (r"payment\s+could\s+not\s+be\s+processed.*update\s+your\s+billing\s+information.*avoid\s+interruption", 
         "Context: Standard Billing Retry — Routine subscription billing notification without suspicious links."),
        
        (r"the\s+address\s+provided\s+appears\s+incomplete.*please\s+confirm\s+your\s+address\s+so\s+we\s+can\s+complete", 
         "Context: Routine Delivery Confirmation — Standard courier address clarification without payment demand."),
        
        (r"subscription\s+is\s+scheduled\s+for\s+renewal.*payment\s+method\s+ending\s+in\s+\d+\s+will\s+be\s+charged", 
         "Context: Recurring Subscription Notice — Standard automated renewal notice."),
        
        (r"new\s+beneficiary\s+was\s+added\s+to\s+your\s+account", 
         "Context: Beneficiary Addition Alert — Transaction confirmation advising the user to verify in-app if unapproved."),
        
        (r"refund\s+has\s+been\s+initiated\s+for\s+the\s+returned\s+item", 
         "Context: E-Commerce Refund Confirmation — Routine notification outlining refund timelines."),
        
        (r"recent\s+order\s+is\s+currently\s+on\s+hold.*check\s+your\s+order\s+status\s+through\s+the\s+retailer's\s+website", 
         "Context: Order Tracking Advisory — Standard update instructing the user to check the retailer website."),
        
        (r"selected\s+for\s+a\s+security\s+review.*support\s+team\s+may\s+contact\s+you\s+shortly", 
         "Context: Routine Support Advisory — Non-coercive notification of an internal review."),
        
        (r"couldn't\s+complete\s+your\s+recent\s+transfer\s+because\s+the\s+recipient\s+information", 
         "Context: Failed Transaction Notice — Informs the user of transfer errors without credential harvesting."),
        
        (r"change\s+the\s+email\s+address\s+associated\s+with\s+your\s+account.*if\s+you\s+did\s+not\s+request\s+this,\s+contact\s+support", 
         "Context: Account Security Alert — Directs user to the official website support if unauthorized."),
        
        (r"delivery\s+preferences\s+have\s+not\s+been\s+updated\s+recently", 
         "Context: User Profile Reminder — Routine profile checkup without urgency."),
        
        (r"(account\s+statement|statement\s+for|monthly\s+account\s+summary).*(available|generated|ready)", 
         "Context: Account Statement Alert — Informs user of periodic statement availability."),
        
        (r"bank\s+has\s+credited.*(check\s+your\s+official|details)", 
         "Context: Account Credit Confirmation — Standard deposit notification advising verification on official app."),
        
        (r"(insurance\s+premium|bill|payment)\s+of\s+.*is\s+due\s+on", 
         "Context: Periodic Billing Reminder — Routine calendar notification for insurance/utility payments."),
        
        (r"(credit\s+card\s+payment|bill)\s+is\s+due\s+on", 
         "Context: Credit Card Due Date Alert — Regular billing notice specifying standard calendar dates."),
        
        (r"due\s+on\s+\d+\s+(january|february|march|april|may|june|july|august|september|october|november|december)", 
         "Context: Calendar Schedule Reminder — Legitimate monthly billing notice."),
        
        (r"appointment\s+is\s+confirmed\s+for", 
         "Context: Booking Confirmation — Standard service/appointment reservation receipt."),
        
        (r"(order|food\s+delivery)\s+(has\s+been\s+shipped|is\s+arriving|arriving\s+today|will\s+arrive)", 
         "Context: Delivery Progress Alert — Standard tracking update from delivery services."),
        
        (r"flight\s+booking\s+is\s+confirmed.*booking\s+reference", 
         "Context: Travel Reservation Receipt — Standard airline ticket confirmation with reference code."),
        
        (r"mobile\s+recharge\s+of\s+.*was\s+successful", 
         "Context: Transaction Receipt — Confirmation receipt for prepaid telecom recharge."),
        
        (r"subscription\s+payment\s+was\s+successful", 
         "Context: Subscription Renewal Receipt — Standard confirmation for automated recurring service charges."),
        
        (r"meeting\s+has\s+been\s+moved\s+from", 
         "Context: Calendar Schedule Update — Routine business schedule modification."),
        
        (r"selected\s+for\s+an\s+interview.*(careers\s+portal|company)", 
         "Context: Career Communication — Standard HR interview invitation pointing to verified company portal."),
        
        (r"friend\s+has\s+sent\s+you\s+a\s+birthday\s+gift.*contact\s+them\s+directly", 
         "Context: Personal Social Notification — Safe gift announcement instructing direct contact."),
        
        (r"bank\s+branch\s+will\s+be\s+closed.*due\s+to\s+a\s+public\s+holiday", 
         "Context: Operational Notice — Standard branch holiday advisory.")
    ]

    is_whitelisted = False
    whitelist_reasons = []
    for pattern, desc in legit_rules:
        if re.search(pattern, normalized_text):
            is_whitelisted = True
            whitelist_reasons.append(desc)

    # 3. Malicious Scam Triggers (Protected from matching negative safety advisories)
    scam_triggers = [
        # Two-Way SMS Phishing
        (
            r"please\s+reply\s+(yes|with|to)\b.*(representative|assist|verification\s+code|transaction)",
            90.0,
            "Interactive SMS Phishing (SMiShing)",
            "Context: Two-Way SMS Engagement — Solicits an active reply via SMS to lure the victim into live credential extraction."
        ),
        (
            r"routine\s+verification\s+check.*replying\s+to\s+this\s+message",
            90.0,
            "Transactional Spoofing / Phishing",
            "Context: Transaction Verification Lure — Prompts an unauthenticated message reply under the guise of an ongoing purchase review."
        ),
        (
            r"annual\s+review.*(confirm\s+your\s+date\s+of\s+birth|registered\s+address).*replying",
            92.0,
            "Personal Data Harvesting",
            "Context: Identity Harvesting — Requests sensitive Personally Identifiable Information (PII) like date of birth or address via unsecured text reply."
        ),
        (
            r"updating\s+our\s+customer\s+records.*(confirm\s+that\s+your\s+mobile\s+number|responding\s+with\s+the\s+number)",
            90.0,
            "SIM / Account Verification Scam",
            "Context: Telecom/SIM Harvesting — Requests active phone verification details to prepare for SIM swap or unauthorized onboarding."
        ),
        (
            r"membership\s+benefits\s+are\s+about\s+to\s+expire.*confirm\s+your\s+account\s+information\s+before\s+the\s+renewal",
            88.0,
            "Subscription Phishing / Renewal Lure",
            "Context: Membership Lure — Fabricates an expiring membership or loyalty perk to solicit account credentials."
        ),
        (
            r"account\s+may\s+be\s+subject\s+to\s+temporary\s+restrictions.*(finish\s+the\s+review|verification\s+is\s+not\s+completed)",
            90.0,
            "Account Coercion / Restriction Phishing",
            "Context: Coercive Account Threat — Threatens imminent account restrictions or freezes to manipulate the user into unverified portals."
        ),
        (
            r"(prevent\s+your\s+order\s+from\s+being\s+cancelled|unable\s+to\s+verify\s+your\s+recent\s+payment).*confirm\s+the\s+payment\s+details",
            89.0,
            "Order Cancellation / Payment Phishing",
            "Context: Order Interruption Lure — Generates panic regarding order cancellation to force re-entry of card/banking data."
        ),
        
        # Digital Arrest & Authority Coercion
        (
            r"(police|cbi|customs|court|trai|narcotics).*(illegal\s+transaction|arrested|case|fir|penalty|warrant).*(pay|transfer|immediately|fine)",
            96.0,
            "Digital Arrest / Authority Impersonation",
            "Context: Digital Arrest Extortion — Coercive intimidation falsely impersonating law enforcement officers with threats of immediate arrest or fines."
        ),
        (
            r"illegal\s+transaction.*(pay|transfer|arrested)",
            95.0,
            "Digital Arrest / Authority Extortion",
            "Context: Legal Extortion Threat — Demands urgent fund transfers to avoid prosecution for alleged illegal account transactions."
        ),

        # Upfront Fee / Work-From-Home / Prize Fraud
        (
            r"(earn|work\s+from\s+home|daily\s+income|job|bonus).*(pay|registration\s+fee|deposit|charge)",
            93.0,
            "Job / Work-From-Home Advance Fee Scam",
            "Context: Work-From-Home Advance Fee — Promises lucrative daily earnings while demanding an upfront registration/portal charge."
        ),
        (
            r"(pay|transfer|refundable\s+fee|processing\s+fee|verification\s+charges?|delivery\s+charges?).*(₹|\b\d+\b|fee|charges?).*(claim|receive|prize|won|gift|benefit|reschedule)",
            94.0,
            "Advance Fee / Lottery Fraud",
            "Context: Advance Fee Demand — Demands an upfront processing, customs, or delivery fee before releasing a prize, gift, or parcel."
        ),
        (
            r"(won|winner|lucky\s+draw|selected\s+for\s+a\s+free|win\s+\d+\s+lakh|claim\s+your\s+(prize|reward))",
            90.0,
            "Lottery / Prize Fraud",
            "Context: Fake Lottery/Prize Lure — Unsolicited notification claiming a high-value lottery or reward prize."
        ),
        (
            r"government\s+benefit.*(pay|charges?|submit|aadhaar|pan)",
            92.0,
            "Government Scheme Phishing",
            "Context: Government Benefit Spoofing — Fabricates official welfare/subsidy approvals to demand processing fees and identity documents."
        ),

        # Credential & OTP Theft (Excludes safe warnings like 'never share OTP' or 'do not share')
        (
            r"(?<!never\s)(?<!do\snot\s)(?<!don\'t\s)(send|forward|share|tell\s+us|provide|enter\s+your)\s+(your|the)?\s*(otp|verification\s+code|pin|card\s+details|cvv|expiry\s+date)",
            98.0,
            "Credential Harvesting / OTP Theft",
            "Context: Direct OTP / PIN Extraction — Explicitly prompts disclosure of confidential 6-digit OTPs, card CVV, or banking PINs."
        ),
        (
            r"(unusual\s+activity|detected\s+suspicious|accessed\s+elsewhere).*(send|provide|share|confirm).*(otp|code|identity)",
            98.0,
            "Account Takeover / OTP Phishing",
            "Context: Account Takeover Phishing — Creates a deceptive security warning to solicit multi-factor authentication (MFA/OTP) tokens."
        ),

        # Service & Utility Disconnection Threats
        (
            r"(disconnected|stop\s+working|deactivated|cancelled|blocked|deleted|locked).*(in\s+\d+\s+(hours?|minutes?)|tonight|today|immediately|unless\s+you\s+pay).*(pay|link|call|provide|confirm)",
            95.0,
            "Urgent Service Suspension Phishing",
            "Context: Utility/Service Disconnection Panic — Fabricates imminent power/SIM suspension to force hasty payments."
        ),
        (
            r"(final\s+warning|urgent).*(cancelled|disconnected|blocked).*(pay|link|call)",
            94.0,
            "Coercive Urgency / Extortion",
            "Context: Coercive Panic Trigger — Uses high-pressure countdowns and 'FINAL WARNING' language to induce panic."
        ),
        (
            r"(account|sim).*(stop\s+working|deleted|deactivated|blocked).*(click|link|confirm|reactivate)",
            93.0,
            "Account Takeover Phishing",
            "Context: SIM/Account Deactivation Lure — Uses service suspension threats to direct victims to external reactivation links."
        ),

        # Impersonation & Accidental Money Transfer Claims
        (
            r"(accidentally\s+received|by\s+mistake|lost\s+my\s+phone).*(return|transfer|send).*(upi|id|account)",
            90.0,
            "Impersonation / False Refund Scam",
            "Context: Fake Refund / Mistaken UPI Transfer — Claims money was sent by mistake to induce a voluntary reverse UPI payment."
        ),

        # Package / Parcel Reschedule Charges
        (
            r"(package|parcel)\s+could\s+not\s+be\s+delivered.*pay\s+.*(reschedule|link)",
            92.0,
            "Delivery Impersonation Scam",
            "Context: Courier Delivery Fee Lure — Exploits pending package deliveries by demanding payment to reschedule."
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

    # 4. Contextual Deep Link & Domain Reputation Analysis
    has_dangerous_domain = False
    for domain in domain_inspections:
        url_str = domain.get('url', '')
        
        if domain.get('impersonated_brand'):
            scam_score = max(scam_score, 95.0)
            has_dangerous_domain = True
            detected_category = "Brand Impersonation / Deceptive Domain"
            reasons.append(f"Context: Domain Spoofing — URL mimics '{domain['impersonated_brand']}' on an unauthorized host ({domain['hostname']}).")

        if domain.get('is_ip'):
            scam_score = max(scam_score, 92.0)
            has_dangerous_domain = True
            detected_category = "Malicious Direct-IP URL"
            reasons.append(f"Context: Numeric IP Endpoint — Uses a raw IP address ({url_str}) commonly configured by phishing gateways.")

        if domain.get('has_suspicious_tld'):
            scam_score = max(scam_score, 88.0)
            has_dangerous_domain = True
            if not detected_category or detected_category == "Legitimate / Safe":
                detected_category = "Suspicious Phishing Gateway"
            reasons.append(f"Context: High-Risk Phishing TLD — Domain uses a disposable or high-risk extension ({domain['hostname']}).")

        if domain.get('is_insecure_http'):
            scam_score = max(scam_score, 70.0)
            has_dangerous_domain = True
            reasons.append(f"Context: Insecure HTTP Protocol — Connection lacks SSL/HTTPS encryption ({url_str}).")

        if domain.get('has_phish_words'):
            scam_score = max(scam_score, 88.0)
            has_dangerous_domain = True
            if not detected_category or detected_category == "Legitimate / Safe":
                detected_category = "Credential Phishing Gateway"
            reasons.append(f"Context: Deceptive Link Keywords — Path or domain contains sensitive authentication triggers in '{url_str}'.")

    # 5. Synthetic Screenshot Artifacts
    if is_synthetic:
        scam_score = max(scam_score, 85.0)
        if not detected_category or detected_category == "Legitimate / Safe":
            detected_category = "Synthetic / Altered Receipt"
        reasons.append("Context: Visual Artifacts — Noise entropy and compression signatures indicate a synthetically altered payment screenshot.")

    # 6. Priority Scoring & Decision Logic
    # If explicitly whitelisted and NO dangerous links/domains were attached, force Safe
    if is_whitelisted and not has_dangerous_domain and scam_score < 80.0:
        final_score = 4.0
        category = "Legitimate / Safe"
        risk_level = "Safe / Low Risk"
        reasons = whitelist_reasons
    elif scam_score > 0:
        final_score = max(ml_score, scam_score)
        category = detected_category
        risk_level = "High Threat" if final_score >= 75 else "Moderate Suspicion"
    elif is_whitelisted:
        final_score = 4.0
        category = "Legitimate / Safe"
        risk_level = "Safe / Low Risk"
        reasons = whitelist_reasons
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
        reasons.append("Context: Clean Verification — No coercive phrases, suspicious links, or deceptive artifacts detected.")

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "category": category,
        "reasons": reasons
    }
