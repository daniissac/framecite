FROM python:3.11-slim

WORKDIR /app

# Install tcpdump and other dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
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

# Create uploads directory
RUN mkdir -p uploads

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
