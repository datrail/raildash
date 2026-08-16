FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY raildash/ ./raildash/
COPY webhook_server.py openapi.yaml ./

# The database lives on a volume or it does not survive the container. Left
# unmounted it still works — it just forgets, which is the behaviour the old
# in-memory server had and the reason this one persists.
ENV RAILDASH_DB=/data/raildash.db
RUN mkdir -p /data && chown 65532:65532 /data
VOLUME /data

USER 65532:65532
EXPOSE 8000

# 0.0.0.0 here, unlike the CLI's 127.0.0.1 default: inside a container the
# network namespace is the boundary, and binding loopback would make the
# published port unreachable. The operator still chooses what to publish.
CMD ["uvicorn", "raildash.app:app", "--host", "0.0.0.0", "--port", "8000"]
