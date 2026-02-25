## PacketPilot

PacketPilot is a comprehensive packet analysis tool that integrates with multiple LLM providers and offers a web-based interface for analyzing network traffic.

### Architecture

- A **FastAPI backend** for processing PCAP files and exposing APIs
- A **Streamlit frontend** dashboard with interactive visualizations and chat interface
- **LLM integration** with multiple providers (OpenAI, Anthropic Claude, Google Gemini, and Ollama)
- **Docker containerization** for easy deployment

### Key Features

1. **PCAP Processing**
   - Upload and analyze PCAP files using Scapy
   - Extract detailed packet information and generate summaries

2. **Visual Analytics Dashboard**
   - Protocol distribution charts
   - Top talkers visualization (IPv4 and IPv6)
   - Connection analysis
   - Interactive packet explorer with pagination

3. **LLM-Powered Analysis**
   - Chat interface for asking natural language questions about the capture
   - Support for multiple LLM providers with automatic fallback
   - Contextual prompting to get relevant insights

4. **Deployment**
   - Docker Compose configuration for containerized deployment
   - Health checks for service readiness
   - Environment variable configuration for API keys and tuning

### Usage Instructions

1. **Setup**
   ```bash
   # Clone and navigate to the directory
   cd packetpilot

   # Configure API keys
   cp .env.template .env
   # Edit .env with your API keys

   # Start the containers
   docker compose up -d
   ```

2. **Access the Dashboard**
   - Open your browser and navigate to http://localhost:8501
   - Upload a PCAP file using the sidebar
   - Explore the visualizations and packet details
   - Ask questions using the Chat Analysis tab

### Configuration

All configuration is done through environment variables. Copy `.env.template` to `.env` and adjust as needed.

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key | (none) |
| `ANTHROPIC_API_KEY` | Anthropic API key | (none) |
| `GEMINI_API_KEY` | Google Gemini API key | (none) |
| `OLLAMA_ENDPOINT` | Ollama API endpoint | `http://ollama:11434/api/generate` |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4-turbo` |
| `ANTHROPIC_MODEL` | Anthropic model name | `claude-3-sonnet-20240229` |
| `GEMINI_MODEL` | Gemini model name | `gemini-pro` |
| `OLLAMA_MODEL` | Ollama model name | `llama2` |
| `MAX_UPLOAD_SIZE_MB` | Maximum PCAP upload size in MB | `100` |
| `MAX_SESSIONS` | Maximum concurrent sessions before LRU eviction | `50` |
| `CORS_ORIGINS` | Comma-separated allowed CORS origins | `http://localhost:8501,http://frontend:8501` |

At least one LLM provider API key must be configured for chat analysis to work. Ollama is always available when the container is running.

The tool provides a user-friendly interface for network analysts to work with packet captures and get AI-assisted insights, making it easier to understand complex network traffic patterns.
