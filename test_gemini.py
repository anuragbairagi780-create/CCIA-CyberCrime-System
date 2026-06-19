from dotenv import load_dotenv
import os
import sys


def main() -> int:
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
    API_KEY = os.getenv("GEMINI_API_KEY")
    print("GEMINI_API_KEY present:", bool(API_KEY))
    if not API_KEY:
        print("No API key found in .env")
        return 2

    try:
        from google import genai
    except Exception as e:
        print("Failed to import google.genai:", e)
        return 3

    try:
        client = genai.Client(api_key=API_KEY)
        print("Client instantiated successfully")
        # Do not make API calls to avoid charges; just confirm instantiation.
        return 0
    except Exception as e:
        print("Failed to instantiate client:", e)
        return 4


if __name__ == "__main__":
    sys.exit(main())
