def get_recommendations(category):
    recommendations = {
        "UPI Fraud": [
            "Block the UPI ID immediately",
            "Contact your bank",
            "Report on cybercrime portal",
            "Save transaction records"
        ],

        "OTP Fraud": [
            "Change banking credentials",
            "Contact bank helpline",
            "Monitor account activity"
        ],

        "Banking Fraud": [
            "Freeze affected accounts",
            "Inform your bank",
            "Collect transaction evidence"
        ],

        "Investment Scam": [
            "Avoid further payments",
            "Save screenshots and chats",
            "Report the platform"
        ],

        "Job Scam": [
            "Stop communication",
            "Do not share documents",
            "Report suspicious recruiter"
        ],

        "KYC Scam": [
            "Do not share KYC details",
            "Inform your bank",
            "Change passwords if shared"
        ]
    }

    return recommendations.get(
        category,
        ["Collect evidence and report the incident"]
    )