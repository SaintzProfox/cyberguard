FROM python:3.12-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y \
    nmap \
    openssl \
    whois \
    curl \
    dnsutils \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories for outputs
RUN mkdir -p /app/scan_results /app/reports

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
