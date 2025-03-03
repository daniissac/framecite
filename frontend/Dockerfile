FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Expose port
EXPOSE 8501

# Environment variables
ENV API_URL="http://backend:8000"

# Start application
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
