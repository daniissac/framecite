FROM python:3.11-slim

WORKDIR /app

# Install tcpdump and other dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .
COPY packet_parser.py .
COPY llm_router.py .

# Create non-root user and uploads directory
RUN groupadd -r appuser && useradd -r -g appuser appuser \
    && mkdir -p uploads && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
