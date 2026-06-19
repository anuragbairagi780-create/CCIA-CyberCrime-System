def generate_report(
    complaint,
    entities,
    category,
    risk,
    legal,
    recommendations
):
    report = f"""
==============================
CCIA AI ANALYSIS REPORT
==============================

Complaint:
{complaint}

------------------------------
Detected Category
------------------------------
{category}

------------------------------
Extracted Entities
------------------------------
Phones: {entities['phones']}
Emails: {entities['emails']}
UPI IDs: {entities['upi_ids']}
URLs: {entities['urls']}

------------------------------
Risk Assessment
------------------------------
Score: {risk['score']}
Level: {risk['level']}

------------------------------
Applicable Laws
------------------------------
Acts:
{chr(10).join(legal['acts'])}

Sections:
{chr(10).join(legal['sections'])}

------------------------------
Recommended Actions
------------------------------
{chr(10).join(recommendations)}

==============================
END OF REPORT
==============================
"""
    return report