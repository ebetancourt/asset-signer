# Build context is the repo root (see docker-compose.yml) because this image
# needs both signer/ (the pipeline it wraps) and server/ (itself).
FROM python:3.12-slim

WORKDIR /app
COPY signer/ signer/
COPY server/ server/

RUN pip install --no-cache-dir ./signer ./server

WORKDIR /app/server
EXPOSE 8000

CMD ["uvicorn", "asset_signer_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
