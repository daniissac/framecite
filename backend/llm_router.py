import os
import json
import enum
import logging
import asyncio
from typing import Dict, Any, Optional, List
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

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
        
        self.endpoints = {
            LLMProvider.OPENAI: "https://api.openai.com/v1/chat/completions",
            LLMProvider.ANTHROPIC: "https://api.anthropic.com/v1/messages",
            LLMProvider.GEMINI: "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
            LLMProvider.OLLAMA: os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/generate")
        }
        
        # Verify necessary API keys
        for provider, key in self.api_keys.items():
            if not key and provider != LLMProvider.OLLAMA:
                logger.warning(f"No API key found for {provider}. This provider will not be available.")
    
    async def query(self, query: str, context: str, provider: LLMProvider = LLMProvider.ANTHROPIC) -> str:
        """
        Send a query to the specified LLM provider.
        
        Args:
            query: The user's query
            context: Context information from the PCAP file
            provider: The LLM provider to use
        
        Returns:
            str: The LLM's response
        """
        # If the provider isn't available, fallback to an available one
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
    
    async def _query_openai(self, query: str, context: str) -> str:
        """Query the OpenAI API."""
        system_prompt = """
You are a network packet analysis assistant. You analyze PCAP files and help users understand network traffic.
Use the provided context to answer questions about the network capture.
If you don't know the answer, say so rather than making up information.
        """
        
        payload = {
            "model": "gpt-4-turbo",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Context from PCAP file:\n{context}\n\nUser question: {query}"}
            ],
            "temperature": 0.7,
            "max_tokens": 1500
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_keys[LLMProvider.OPENAI]}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.OPENAI],
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            response_data = response.json()
            return response_data["choices"][0]["message"]["content"]
    
    async def _query_anthropic(self, query: str, context: str) -> str:
        """Query the Anthropic API."""
        system_prompt = """
You are a network packet analysis assistant. You analyze PCAP files and help users understand network traffic.
Use the provided context to answer questions about the network capture.
If you don't know the answer, say so rather than making up information.
        """
        
        payload = {
            "model": "claude-3-sonnet-20240229",
            "max_tokens": 1500,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": f"Context from PCAP file:\n{context}\n\nUser question: {query}"}
            ]
        }
        
        headers = {
            "x-api-key": self.api_keys[LLMProvider.ANTHROPIC],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.ANTHROPIC],
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            response_data = response.json()
            return response_data["content"][0]["text"]
    
    async def _query_gemini(self, query: str, context: str) -> str:
        """Query the Google Gemini API."""
        endpoint = f"{self.endpoints[LLMProvider.GEMINI]}?key={self.api_keys[LLMProvider.GEMINI]}"
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"""
You are a network packet analysis assistant. You analyze PCAP files and help users understand network traffic.
Use the provided context to answer questions about the network capture.
If you don't know the answer, say so rather than making up information.

Context from PCAP file:
{context}

User question: {query}
                            """
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 1500
            }
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                endpoint,
                json=payload,
                headers=headers
            )
            response.raise_for_status()
            response_data = response.json()
            return response_data["candidates"][0]["content"]["parts"][0]["text"]
    
    async def _query_ollama(self, query: str, context: str) -> str:
        """Query a local Ollama instance."""
        payload = {
            "model": os.getenv("OLLAMA_MODEL", "llama2"),
            "prompt": f"""
You are a network packet analysis assistant. You analyze PCAP files and help users understand network traffic.
Use the provided context to answer questions about the network capture.
If you don't know the answer, say so rather than making up information.

Context from PCAP file:
{context}

User question: {query}
            """,
            "stream": False
        }
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                self.endpoints[LLMProvider.OLLAMA],
                json=payload
            )
            response.raise_for_status()
            response_data = response.json()
            return response_data["response"]
