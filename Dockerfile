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

# Run the dashboard server. A container has to bind 0.0.0.0 to be reachable
# through a published port, and the server refuses that bind without a token,
# so the container will not start unauthenticated:
#   docker run -e CIPHERGUARD_TOKEN=$(openssl rand -hex 32) -p 8000:8000 <image>
CMD ["python", "-m", "cipherguard.cli", "serve", "--host", "0.0.0.0"]
