import os
import enum
import logging
from typing import Optional, List
import httpx

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a network packet analysis assistant. You analyze PCAP files and "
    "help users understand network traffic. Use the provided context to answer "
    "questions about the network capture. If you don't know the answer, say so "
    "rather than making up information."
)


class LLMProvider(str, enum.Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class LLMRouter:
    def __init__(self):
        """Initialize the LLM router with API keys from environment variables."""
        self.api_keys = {
            LLMProvider.OPENAI: os.getenv("OPENAI_API_KEY"),
            LLMProvider.ANTHROPIC: os.getenv("ANTHROPIC_API_KEY"),
            LLMProvider.GEMINI: os.getenv("GEMINI_API_KEY"),
        }

        self.models = {
            LLMProvider.OPENAI: os.getenv("OPENAI_MODEL", "gpt-4-turbo"),
            LLMProvider.ANTHROPIC: os.getenv("ANTHROPIC_MODEL", "claude-3-sonnet-20240229"),
            LLMProvider.GEMINI: os.getenv("GEMINI_MODEL", "gemini-pro"),
            LLMProvider.OLLAMA: os.getenv("OLLAMA_MODEL", "llama2"),
        }

        gemini_model = self.models[LLMProvider.GEMINI]
        self.endpoints = {
            LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
            LLMProvider.ANTHROPIC: "https://api.anthropic.com/v1/messages",
            LLMProvider.GEMINI: f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent",
            LLMProvider.OLLAMA: os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/generate"),
        }

        for provider, key in self.api_keys.items():
            if not key and provider != LLMProvider.OLLAMA:
                logger.warning(f"No API key found for {provider}. This provider will not be available.")

    def get_available_providers(self) -> List[str]:
        """Return provider names that have API keys configured (Ollama is always available)."""
        available = []
        for provider in LLMProvider:
            if provider == LLMProvider.OLLAMA or self.api_keys.get(provider):
                available.append(provider.value)
        return available

    async def query(self, query: str, context: str, provider: LLMProvider = LLMProvider.ANTHROPIC) -> str:
        if provider != LLMProvider.OLLAMA and not self.api_keys.get(provider):
            available_providers = [p for p in LLMProvider if p == LLMProvider.OLLAMA or self.api_keys.get(p)]
            if not available_providers:
                return "No LLM providers are available. Please check your API keys."
            provider = available_providers[0]
            logger.info(f"Falling back to {provider} provider")

        try:
            if provider == LLMProvider.OPENAI:
                return await self._query_openai(query, context)
            elif provider == LLMProvider.ANTHROPIC:
                return await self._query_anthropic(query, context)
            elif provider == LLMProvider.GEMINI:
                return await self._query_gemini(query, context)
            elif provider == LLMProvider.OLLAMA:
                return await self._query_ollama(query, context)
            else:
                return f"Unsupported LLM provider: {provider}"
        except Exception as e:
            logger.error(f"Error querying {provider}: {str(e)}")
            return f"Error querying {provider}: {str(e)}"

    def _build_user_message(self, query: str, context: str) -> str:
        return f"Context from PCAP file:\n{context}\n\nUser question: {query}"

    async def _query_openai(self, query: str, context: str) -> str:
        """Query the OpenAI API."""
        payload = {
            "model": self.models[LLMProvider.OPENAI],
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": self._build_user_message(query, context)},
            ],
            "temperature": 0.7,
            "max_tokens": 1500,
        }

        headers = {
            "Authorization": f"Bearer {self.api_keys[LLMProvider.OPENAI]}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.OPENAI],
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            response_data = response.json()
            choices = response_data.get("choices")
            if not choices or not isinstance(choices, list):
                raise ValueError("Unexpected OpenAI response structure: missing 'choices'")
            return choices[0].get("message", {}).get("content", "")

    async def _query_anthropic(self, query: str, context: str) -> str:
        """Query the Anthropic API."""
        payload = {
            "model": self.models[LLMProvider.ANTHROPIC],
            "max_tokens": 1500,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": self._build_user_message(query, context)},
            ],
        }

        headers = {
            "x-api-key": self.api_keys[LLMProvider.ANTHROPIC],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.ANTHROPIC],
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            response_data = response.json()
            content = response_data.get("content")
            if not content or not isinstance(content, list):
                raise ValueError("Unexpected Anthropic response structure: missing 'content'")
            return content[0].get("text", "")

    async def _query_gemini(self, query: str, context: str) -> str:
        """Query the Google Gemini API."""
        user_text = f"{SYSTEM_PROMPT}\n\n{self._build_user_message(query, context)}"
        payload = {
            "contents": [{"parts": [{"text": user_text}]}],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 1500,
            },
        }

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_keys[LLMProvider.GEMINI],
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.GEMINI],
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            response_data = response.json()
            candidates = response_data.get("candidates")
            if not candidates or not isinstance(candidates, list):
                raise ValueError("Unexpected Gemini response structure: missing 'candidates'")
            parts = candidates[0].get("content", {}).get("parts")
            if not parts or not isinstance(parts, list):
                raise ValueError("Unexpected Gemini response structure: missing 'parts'")
            return parts[0].get("text", "")

    async def _query_ollama(self, query: str, context: str) -> str:
        """Query a local Ollama instance."""
        prompt = f"{SYSTEM_PROMPT}\n\n{self._build_user_message(query, context)}"
        payload = {
            "model": self.models[LLMProvider.OLLAMA],
            "prompt": prompt,
            "stream": False,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.OLLAMA],
                json=payload,
            )
            response.raise_for_status()
            response_data = response.json()
            text = response_data.get("response")
            if text is None:
                raise ValueError("Unexpected Ollama response structure: missing 'response'")
            return text
