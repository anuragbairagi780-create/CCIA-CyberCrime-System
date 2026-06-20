from dotenv import load_dotenv
import os

load_dotenv(override=True)

api_key = os.getenv("GEMINI_API_KEY")

print("Loaded:", bool(api_key))

if api_key:
    print("Prefix:", api_key[:10])
else:
    print("No API key found")