import os
from dotenv import load_dotenv
from supabase import create_client, Client
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_groq import ChatGroq

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("❌ Supabase credentials missing in .env file")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

print("Loading Memory (MiniLM Embeddings)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

print("Waking up the Agents...")

llm_junior = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    max_tokens=1024,
    api_key=GROQ_API_KEY
)

llm_senior = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0.1,
    max_tokens=1024,
    api_key=GROQ_API_KEY
)
