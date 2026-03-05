# CodeRisk Advisor — Backend Dockerfile
# Python 3.12 slim — smaller image, faster Cloud Run cold starts

FROM python:3.12-slim

# Prevents Python from writing .pyc files
# Ensures stdout/stderr are unbuffered (important for Cloud Run logging)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first — cached layer if requirements.txt unchanged
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Cloud Run expects the container to listen on $PORT
# Default to 8080 if not set
ENV PORT=8080

EXPOSE 8080

# uvicorn with single worker — Cloud Run scales via instances, not workers
# --proxy-headers required for correct client IP behind Cloud Run's load balancer
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'"]