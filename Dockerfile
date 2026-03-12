FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY pyproject.toml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ src/
COPY configs/ configs/

# Create data directories
RUN mkdir -p data/datasets data/qdrant data/models results logs

EXPOSE 8000

CMD ["python", "-m", "src.main"]
