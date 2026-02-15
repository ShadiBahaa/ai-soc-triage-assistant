"""
LLM client module for AI SOC Analyst.
Provider-agnostic interface for LLM-powered summarization.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def llm_enabled() -> bool:
    """
    Check if LLM integration is enabled.
    
    Returns:
        True if LLM provider is configured, False otherwise
    """
    provider = os.getenv("LLM_PROVIDER", "none").lower()
    return provider not in ("none", "", "disabled")


def get_provider() -> str:
    """Get the configured LLM provider name."""
    return os.getenv("LLM_PROVIDER", "none").lower()


def generate_summary(prompt: str) -> str:
    """
    Generate a summary using the configured LLM provider.
    
    This is a provider-agnostic stub that can be extended to support
    various LLM providers (OpenAI, Anthropic, local models, etc.)
    
    Args:
        prompt: The prompt to send to the LLM
        
    Returns:
        Generated summary text
        
    Raises:
        NotImplementedError: If LLM is not configured
        ValueError: If provider is unknown
    """
    if not llm_enabled():
        raise NotImplementedError(
            "LLM provider not configured. "
            "Set LLM_PROVIDER in .env file or use deterministic summarization mode."
        )
    
    provider = get_provider()
    api_key = os.getenv("LLM_API_KEY", "")
    model = os.getenv("LLM_MODEL", "")
    
    if provider == "openai":
        return _generate_openai(prompt, api_key, model)
    elif provider == "anthropic":
        return _generate_anthropic(prompt, api_key, model)
    elif provider == "local":
        return _generate_local(prompt, model)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


def _generate_openai(prompt: str, api_key: str, model: str) -> str:
    """
    Generate summary using OpenAI API.
    
    Requires: pip install openai
    """
    try:
        import openai
    except ImportError:
        raise ImportError("OpenAI SDK not installed. Run: pip install openai")
    
    if not api_key:
        raise ValueError("LLM_API_KEY not set for OpenAI provider")
    
    client = openai.OpenAI(api_key=api_key)
    model = model or "gpt-4o-mini"
    
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an expert SOC analyst providing incident summaries."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1000,
        temperature=0.3
    )
    
    return response.choices[0].message.content.strip()


def _generate_anthropic(prompt: str, api_key: str, model: str) -> str:
    """
    Generate summary using Anthropic API.
    
    Requires: pip install anthropic
    """
    try:
        import anthropic
    except ImportError:
        raise ImportError("Anthropic SDK not installed. Run: pip install anthropic")
    
    if not api_key:
        raise ValueError("LLM_API_KEY not set for Anthropic provider")
    
    client = anthropic.Anthropic(api_key=api_key)
    model = model or "claude-3-haiku-20240307"
    
    message = client.messages.create(
        model=model,
        max_tokens=1000,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    
    return message.content[0].text.strip()


def _generate_local(prompt: str, model: str) -> str:
    """
    Generate summary using a local model (e.g., Ollama).
    
    Requires a local LLM server running on localhost:11434
    """
    try:
        import requests
    except ImportError:
        raise ImportError("Requests library not installed. Run: pip install requests")
    
    model = model or "llama2"
    
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )
    
    if response.status_code != 200:
        raise RuntimeError(f"Local LLM request failed: {response.text}")
    
    return response.json().get("response", "").strip()
