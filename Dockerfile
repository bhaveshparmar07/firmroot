FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk squashfs-tools binutils cpio gzip xz-utils file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY service/server.py ./

ENV PYTHONPATH=/app/src
ENV PORT=8080
EXPOSE 8080

CMD ["python", "server.py"]
