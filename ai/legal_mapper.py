def get_legal_sections(category):
    laws = {
        "OTP Fraud": {
            "acts": [
                "Information Technology Act 2000",
                "Bharatiya Nyaya Sanhita (BNS)"
            ],
            "sections": [
                "IT Act Section 66D",
                "BNS Cheating & Fraud Provisions"
            ]
        },

        "UPI Fraud": {
            "acts": [
                "Information Technology Act 2000",
                "Bharatiya Nyaya Sanhita (BNS)"
            ],
            "sections": [
                "IT Act Section 66C",
                "IT Act Section 66D"
            ]
        },

        "Banking Fraud": {
            "acts": [
                "Information Technology Act 2000",
                "Bharatiya Nyaya Sanhita (BNS)"
            ],
            "sections": [
                "IT Act Section 66C",
                "IT Act Section 66D"
            ]
        },

        "Investment Scam": {
            "acts": [
                "Information Technology Act 2000",
                "Bharatiya Nyaya Sanhita (BNS)"
            ],
            "sections": [
                "IT Act Section 66D",
                "Cheating & Fraud Provisions"
            ]
        },

        "Job Scam": {
            "acts": [
                "Bharatiya Nyaya Sanhita (BNS)"
            ],
            "sections": [
                "Cheating & Fraud Provisions"
            ]
        },

        "KYC Scam": {
            "acts": [
                "Information Technology Act 2000"
            ],
            "sections": [
                "IT Act Section 66C",
                "IT Act Section 66D"
            ]
        }
    }

    return laws.get(
        category,
        {
            "acts": ["Under Review"],
            "sections": ["Under Review"]
        }
    )