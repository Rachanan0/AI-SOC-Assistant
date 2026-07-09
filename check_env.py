import os
from dotenv import load_dotenv

load_dotenv()

key = os.getenv("OPENAI_API_KEY")

if key:
    print("API Key Loaded")
    print(key[:15] + "...")
else:
    print("API Key Not Found")