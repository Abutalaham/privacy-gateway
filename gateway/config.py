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

ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-haiku-5-5")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
