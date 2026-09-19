FROM python:3.11-slim

WORKDIR /app

# Install system build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and models
COPY . .

# Expose standard web port
ENV PORT=8000
EXPOSE 8000

# Run production dashboard server
CMD ["python", "-m", "cipherguard.cli", "serve", "--host", "0.0.0.0", "--insecure-bind"]
