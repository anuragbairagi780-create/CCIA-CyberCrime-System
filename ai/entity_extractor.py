import re

def extract_entities(text):
    phones = re.findall(r"\b\d{10}\b", text)

    emails = re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        text
    )

    urls = re.findall(
        r"https?://[^\s]+",
        text
    )

    upi_ids = []
    upi_candidates = re.findall(
        r"\b[a-zA-Z0-9._-]+@[a-zA-Z]+\b",
        text
    )

    for candidate in upi_candidates:
        is_email = False

        for email in emails:
            if candidate in email:
                is_email = True
                break

        if not is_email:
            upi_ids.append(candidate)

    return {
        "phones": phones,
        "emails": emails,
        "upi_ids": upi_ids,
        "urls": urls
    }