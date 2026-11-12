"""Central configuration (all overridable with environment variables)."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DB_PATH = os.getenv("PG_DB_PATH", "audit.db")
AUDIT_BACKEND = os.getenv("PG_AUDIT_BACKEND", "sqlite").lower()
SUPABASE_URL = os.getenv("PG_SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("PG_SUPABASE_SERVICE_ROLE_KEY", "")
SCORE_THRESHOLD = float(os.getenv("PG_SCORE_THRESHOLD", "0.35"))

# Detection engine
USE_PRESIDIO = os.getenv("PG_USE_PRESIDIO", "1") == "1"      # falls back to built-in regex engine if import fails
SPACY_MODEL = os.getenv("PG_SPACY_MODEL", "en_core_web_sm")
USE_GLINER = os.getenv("PG_USE_GLINER", "0") == "1"          # local NER model for names + addresses
GLINER_MODEL = os.getenv("PG_GLINER_MODEL", "urchade/gliner_multi_pii-v1")

# LLM routing
LLM_PROVIDER = os.getenv("PG_LLM_PROVIDER", "mock")          # anthropic | openai | ollama | local | mock
FALLBACK = os.getenv("PG_FALLBACK", "local")                 # ollama | local | none
HTTP_TIMEOUT = float(os.getenv("PG_HTTP_TIMEOUT", "30"))
MAX_UPLOAD_BYTES = int(os.getenv("PG_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
MAX_DOCUMENT_CHARS = int(os.getenv("PG_MAX_DOCUMENT_CHARS", "1000000"))
MAX_DOCUMENT_PAGES = int(os.getenv("PG_MAX_DOCUMENT_PAGES", "500"))
OCR_MAX_PAGES = int(os.getenv("PG_OCR_MAX_PAGES", "50"))
OCR_MAX_IMAGE_PIXELS = int(os.getenv("PG_OCR_MAX_IMAGE_PIXELS", "25000000"))
DOCUMENT_TTL_SECONDS = int(os.getenv("PG_DOCUMENT_TTL_SECONDS", "900"))
MAX_ACTIVE_DOCUMENTS = int(os.getenv("PG_MAX_ACTIVE_DOCUMENTS", "100"))
CORS_ORIGINS = [origin.strip() for origin in os.getenv(
    "PG_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",") if origin.strip()]

ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-5-5")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
