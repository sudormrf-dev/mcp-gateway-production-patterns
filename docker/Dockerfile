FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir ".[vault]"

COPY patterns/ ./patterns/
COPY examples/ ./examples/

ENV PYTHONUNBUFFERED=1

CMD ["python", "examples/multi_tenant_server.py"]
