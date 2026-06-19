from ai.entity_extractor import extract_entities
from ai.category_detector import detect_category
from ai.risk_engine import calculate_risk
from ai.legal_mapper import get_legal_sections
from ai.recommendation_engine import get_recommendations

def analyze_complaint(complaint):

    entities = extract_entities(complaint)

    category = detect_category(complaint)

    risk = calculate_risk(
        entities,
        category,
        complaint
    )

    legal = get_legal_sections(category)

    recommendations = get_recommendations(category)

    indicators = []

    indicators.extend(entities["phones"])
    indicators.extend(entities["emails"])
    indicators.extend(entities["upi_ids"])
    indicators.extend(entities["urls"])

    return {
        "case_summary":
            f"Complaint appears related to {category}. "
            f"Detected {len(indicators)} suspicious indicators.",

        "crime_category": category,

        "risk_level": risk["level"],

        "risk_reason":
            f"Risk score calculated as {risk['score']}.",

        "key_indicators": indicators,

        "investigation_steps": recommendations,

        "legal_sections":
            ", ".join(legal["sections"]),

        "priority_action":
            recommendations[0] if recommendations else "Investigate immediately"
    }