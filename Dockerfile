FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY webhook_server.py openapi.yaml ./

USER 65532:65532
EXPOSE 8000
CMD ["uvicorn", "webhook_server:app", "--host", "0.0.0.0", "--port", "8000"]
