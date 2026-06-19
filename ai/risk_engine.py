import re

def calculate_risk(entities, category, complaint_text=""):
    score = 0

    text = complaint_text.lower()

    # Entity Scoring

    if entities["phones"]:
        score += 10

    if entities["emails"]:
        score += 10

    if entities["upi_ids"]:
        score += 20

    if entities["urls"]:
        score += 20

    # Multiple Indicators Bonus

    indicator_count = (
        len(entities["phones"]) +
        len(entities["emails"]) +
        len(entities["upi_ids"]) +
        len(entities["urls"])
    )

    if indicator_count >= 3:
        score += 10

    # Category Scoring

    category_scores = {
        "Investment Scam": 30,
        "UPI Fraud": 25,
        "Banking Fraud": 25,
        "OTP Fraud": 35,
        "Job Scam": 20,
        "Lottery Scam": 20,
        "Social Media Fraud": 20,
        "Loan Scam": 20,
        "KYC Scam": 20,
        "Unknown": 5
    }

    score += category_scores.get(category, 5)

    # Keyword Risk Boost

    if "otp" in text:
        score += 15

    if "kyc" in text:
        score += 10

    if "bank" in text:
        score += 10

    if "account" in text:
        score += 5

    # Money Loss Detection

    if re.search(r'₹\s*\d+', complaint_text):
        score += 15

    if re.search(r'rs\.?\s*\d+', text):
        score += 15

    # Final Limit

    score = min(score, 100)

    # Risk Levels

    if score <= 30:
        level = "Low"

    elif score <= 60:
        level = "Medium"

    elif score <= 85:
        level = "High"

    else:
        level = "Critical"

    return {
        "score": score,
        "level": level
    }