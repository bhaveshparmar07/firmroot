# Use official lightweight Python image
FROM python:3.11-slim

# Install system dependencies (binwalk, squashfs-tools for firmware extraction)
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    squashfs-tools \
    file \
    tar \
    gzip \
    bzip2 \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set Cloud Run port
ENV PORT=8080
EXPOSE 8080

# Execute server
CMD ["python", "server.py"]
