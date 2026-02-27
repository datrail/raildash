# DatRail eBPF Webhook

Captures SSL/TLS traffic from AI agents (e.g. Claude Code) using eBPF sslsniff,
parses HTTP request/response pairs, and forwards them to a webhook endpoint.

## Architecture

```
Claude Code (BoringSSL)
    │
    │ HTTPS to api.anthropic.com
    │
    ▼
eBPF sslsniff ──── kernel-level SSL interception (zero instrumentation)
    │
    │ JSONL (raw SSL events)
    │
    ▼
collector.py ──── parses HTTP, redacts auth, batches events
    │
    │ POST JSON batches
    │
    ▼
webhook_server.py ──── receives, stores, displays
```

## Quick Start

### 1. Start the webhook server

```bash
pip install -r requirements.txt
python3 webhook_server.py
# → http://localhost:8000/
```

### 2. Start the collector (requires root for eBPF)

```bash
# Auto-detect Claude Code binary and forward parsed HTTP interactions
sudo python3 collector.py \
    --auto-detect-claude \
    --webhook http://localhost:8000/webhook/http-interactions \
    --output captured.jsonl

# Or specify binary path manually
sudo python3 collector.py \
    --binary-path ~/.local/share/claude/versions/2.1.61 \
    --webhook http://localhost:8000/webhook/http-interactions

# Forward raw SSL events instead
sudo python3 collector.py \
    --mode raw \
    --auto-detect-claude \
    --webhook http://localhost:8000/webhook/events
```

### 3. Use Claude Code normally

```bash
# In another terminal
claude --model claude-haiku-4-5-20251001
```

The collector captures all HTTPS traffic and forwards it to the webhook.

## API Endpoints

See [openapi.yaml](openapi.yaml) for the full OpenAPI specification.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook/events` | POST | Receive raw SSL events |
| `/webhook/http-interactions` | POST | Receive parsed HTTP request/response pairs |
| `/webhook/health` | GET | Health check |
| `/webhook/sessions` | GET | List capture sessions |
| `/webhook/sessions/{id}` | GET | Get session details |
| `/` | GET | Dashboard UI |

## Data Formats

### Raw SSL Event (from sslsniff)

```json
{
  "function": "WRITE/SEND",
  "timestamp_ns": 242692590000000,
  "comm": "HTTP Client",
  "pid": 12345,
  "tid": 12345,
  "uid": 1000,
  "len": 64163,
  "buf_size": 64163,
  "latency_ms": 0.045,
  "is_handshake": false,
  "data": "POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\n...",
  "truncated": false
}
```

### Parsed HTTP Interaction (from collector.py)

```json
{
  "timestamp": "2026-02-26T10:00:00+00:00",
  "timestamp_ns": 242692590000000,
  "pid": 12345,
  "tid": 12345,
  "uid": 1000,
  "comm": "HTTP Client",
  "request": {
    "method": "POST",
    "path": "/v1/messages?beta=true",
    "headers": {
      "host": "api.anthropic.com",
      "content-type": "application/json",
      "authorization": "[REDACTED]",
      "x-api-key": "[REDACTED]"
    },
    "body": {
      "model": "claude-haiku-4-5-20251001",
      "messages": [...]
    }
  },
  "response": {
    "status_code": 200,
    "status_text": "OK",
    "headers": { "content-type": "text/event-stream; charset=utf-8" },
    "body": "event: message_start\ndata: ...",
    "is_sse": true
  },
  "latency_ms": 1523.4,
  "request_size": 64163,
  "response_size": 1721
}
```

## Collector Options

| Flag | Description | Default |
|------|-------------|---------|
| `--mode {raw,http}` | Forward raw events or parsed HTTP | `http` |
| `--webhook URL` | Webhook URL to POST events to | none |
| `--output FILE` | Save events to JSONL file | none |
| `--binary-path PATH` | Binary with static SSL (Claude Code) | none |
| `--auto-detect-claude` | Auto-find Claude Code binary | off |
| `--pid PID` | Filter by process ID | all |
| `--uid UID` | Filter by user ID | all |
| `--comm NAME` | Filter by process name | all |
| `--batch-size N` | Events per webhook batch | 10 |
| `--flush-interval SECS` | Max seconds between flushes | 2.0 |
| `--sslsniff PATH` | Path to sslsniff binary | auto |
