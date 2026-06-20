def detect_category(text):
    text = text.lower()

    scores = {
        "Investment Scam": 0,
        "OTP Fraud": 0,
        "Banking Fraud": 0,
        "UPI Fraud": 0,
        "Job Scam": 0,
        "KYC Scam": 0
    }

    categories = {
        "Investment Scam": [
            "investment",
            "invest",
            "profit",
            "returns",
            "return",
            "crypto",
            "trading",
            "double money",
            "telegram group",
            "stock market",
            "forex"
        ],

        "OTP Fraud": [
            "otp",
            "verification code",
            "one time password"
        ],

        "Banking Fraud": [
            "bank",
            "bank account",
            "account",
            "debit card",
            "credit card",
            "net banking",
            "ifsc"
        ],

        "UPI Fraud": [
            "upi",
            "paytm",
            "phonepe",
            "gpay",
            "google pay",
            "@paytm",
            "@ybl",
            "@ibl",
            "@axl",
            "@apl"
        ],

        "Job Scam": [
            "job",
            "hiring",
            "vacancy",
            "recruitment",
            "work from home",
            "part time job"
        ],

        "KYC Scam": [
            "kyc",
            "kyc update",
            "kyc verification"
        ]
    }

    # Calculate scores
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword in text:

                if category == "Investment Scam":
                    scores[category] += 4

                elif category == "OTP Fraud":
                    scores[category] += 5

                else:
                    scores[category] += 2

    # Special Priority Rules

    if "otp" in text:
        scores["OTP Fraud"] += 20

    if (
        "investment" in text
        or "profit" in text
        or "returns" in text
        or "crypto" in text
        or "trading" in text
    ):
        scores["Investment Scam"] += 10

    if (
        "@paytm" in text
        or "@ybl" in text
        or "@ibl" in text
    ):
        scores["UPI Fraud"] += 3

    if "bank account" in text:
        scores["Banking Fraud"] += 5

    best_category = max(scores, key=scores.get)

    if scores[best_category] == 0:
        return "Unknown"

    return best_category