from dotenv import load_dotenv
import os
import sys


def main() -> int:
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
    API_KEY = os.getenv("GEMINI_API_KEY")
    if not API_KEY:
        print("No GEMINI_API_KEY found")
        return 2

    try:
        from google import genai
    except Exception as e:
        print("Failed to import google.genai:", e)
        return 3

    client = genai.Client(api_key=API_KEY)

    prompt = "Validate key: reply with OK"
    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        print("API call successful")
        try:
            # Some wrappers return .text, others return a string
            print("Response text:", getattr(response, "text", response))
        except Exception:
            print("Response:", response)
        return 0
    except Exception as e:
        print("API call failed:", e)
        return 4


if __name__ == "__main__":
    sys.exit(main())
