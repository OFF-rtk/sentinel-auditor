import os
import time
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")


if not api_key:
    print("Error: Key not found")
    exit(1)

print("Testing Neural Links...")

print("\n Testing Junior (Llama 3.1 8B)...")
try:
    junior = ChatGroq(model="llama-3.1-8b-instant", api_key = api_key)
    response = junior.invoke("Say 'Junior Online' and nothing else.")
    print(f" Response: {response.content}")
except Exception as e:
    print(f" Junior Failed: {e}")

print("\n Testing Senior (Llama 3.3 70B)...")
try:
    senior = ChatGroq(model="llama-3.3-70b-versatile", api_key = api_key)
    response = senior.invoke("Say 'Senior Online' and nothing else.")
    print(f" Response: {response.content}")
except Exception as e:
    print(f" Senior Failed: {e}")

print("\n System OK")
