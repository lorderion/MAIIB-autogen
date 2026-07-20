from dotenv import load_dotenv
import os

load_dotenv(".env")

Ollama_url = os.getenv("OLLAMA_BASE_URL")
Llama_model = os.getenv("LLM_MODEL")
Gemma_model = os.getenv("GEM_MODEL")

# Llama_prompt = ""
# Gemma_prompt = ""
