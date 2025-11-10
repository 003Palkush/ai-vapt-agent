import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration settings for VAPT Agent"""
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:latest")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    MAX_REASONING_ITERATIONS = int(os.getenv("MAX_REASONING_ITERATIONS", "10"))
    ENABLE_PARALLEL_SCANS = os.getenv("ENABLE_PARALLEL_SCANS", "false").lower() == "true"
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    OUTPUT_DIR = "outputs"
    
    @staticmethod
    def ensure_output_dir():
        """Ensure output directory exists"""
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
