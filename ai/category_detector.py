def detect_category(text):
    text = text.lower()

    categories = {
        "UPI Fraud": [
            "upi", "paytm", "phonepe",
            "gpay", "google pay",
            "@paytm", "@ybl", "@ibl",
            "@axl", "@apl"
        ],

        "OTP Fraud": [
            "otp",
            "verification code",
            "one time password"
        ],

        "Banking Fraud": [
            "bank", "account",
            "debit card",
            "credit card",
            "net banking"
        ],

        "Investment Scam": [
            "investment",
            "invest",
            "profit",
            "returns",
            "crypto",
            "trading",
            "double money"
        ],

        "Job Scam": [
            "job",
            "hiring",
            "vacancy",
            "recruitment",
            "work from home"
        ],

        "KYC Scam": [
            "kyc",
            "kyc update",
            "kyc verification"
        ]
    }

    scores = {}

    for category, keywords in categories.items():
        score = 0

        for keyword in keywords:
            if keyword in text:
                score += 2

        scores[category] = score

    # Special Priority Rules

    if "@paytm" in text or "@ybl" in text or "@ibl" in text:
        scores["UPI Fraud"] += 5

    if "otp" in text:
        scores["OTP Fraud"] += 15

    if "bank account" in text:
        scores["Banking Fraud"] += 5

    best_category = max(scores, key=scores.get)

    if scores[best_category] == 0:
        return "Unknown"

    return best_category