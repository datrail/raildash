#!/usr/bin/env python3
"""
eBPF SSL Collector — wraps sslsniff, parses HTTP, and forwards to webhook.

Usage:
    # Forward raw SSL events to webhook
    sudo python3 collector.py --mode raw --webhook http://localhost:8000/webhook/events

    # Forward parsed HTTP interactions to webhook
    sudo python3 collector.py --mode http --webhook http://localhost:8000/webhook/http-interactions

    # Just capture to file (no webhook)
    sudo python3 collector.py --mode http --output captured.jsonl

    # Monitor Claude Code specifically
    sudo python3 collector.py --mode http --binary-path ~/.local/share/claude/versions/2.1.61 \\
        --webhook http://localhost:8000/webhook/http-interactions
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

SSLSNIFF_PATH = str(
    Path(__file__).resolve().parent.parent
    / "third_party"
    / "agentsight"
    / "bpf"
    / "sslsniff"
)

# ─── HTTP Parsing ───────────────────────────────────────────────────────────

_HTTP_REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(\S+)\s+HTTP/\d\.\d\r?\n"
)
_HTTP_RESPONSE_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})\s*(.*?)\r?\n")


def parse_http_request(data: str) -> Optional[dict]:
    """Parse a raw HTTP request string into structured dict."""
    m = _HTTP_REQUEST_RE.match(data)
    if not m:
        return None
    method, path = m.group(1), m.group(2)

    # Split headers and body
    parts = re.split(r"\r?\n\r?\n", data, maxsplit=1)
    header_block = parts[0]
    body_raw = parts[1] if len(parts) > 1 else ""

    # Parse headers
    headers = {}
    for line in header_block.split("\n")[1:]:  # skip request line
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower()
            # Redact auth headers
            if key in ("authorization", "x-api-key"):
                headers[key] = "[REDACTED]"
            else:
                headers[key] = v.strip()

    # Try parsing body as JSON
    body = body_raw
    if body_raw:
        try:
            body = json.loads(body_raw)
        except (json.JSONDecodeError, ValueError):
            pass

    return {"method": method, "path": path, "headers": headers, "body": body}


def parse_http_response(data: str) -> Optional[dict]:
    """Parse a raw HTTP response string into structured dict."""
    m = _HTTP_RESPONSE_RE.match(data)
    if not m:
        return None
    status_code = int(m.group(1))
    status_text = m.group(2).strip()

    parts = re.split(r"\r?\n\r?\n", data, maxsplit=1)
    header_block = parts[0]
    body_raw = parts[1] if len(parts) > 1 else ""

    headers = {}
    for line in header_block.split("\n")[1:]:
        line = line.strip()
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    is_sse = "text/event-stream" in headers.get("content-type", "")

    body = body_raw
    if body_raw and not is_sse:
        try:
            body = json.loads(body_raw)
        except (json.JSONDecodeError, ValueError):
            pass

    return {
        "status_code": status_code,
        "status_text": status_text,
        "headers": headers,
        "body": body,
        "is_sse": is_sse,
    }


# ─── Boot time for timestamp conversion ────────────────────────────────────

def get_boot_time() -> float:
    """Get system boot time in seconds (from /proc/stat)."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError):
        pass
    return time.time()


_BOOT_TIME = get_boot_time()


def ns_to_datetime(timestamp_ns: int) -> str:
    """Convert bpf_ktime_get_ns timestamp to ISO datetime string."""
    epoch_s = _BOOT_TIME + timestamp_ns / 1e9
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).isoformat()


# ─── Webhook sender ────────────────────────────────────────────────────────

def send_to_webhook(url: str, payload: dict) -> bool:
    """POST JSON payload to webhook URL. Returns True on success."""
    data = json.dumps(payload, default=str).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except (URLError, OSError) as e:
        print(f"[webhook] Error sending to {url}: {e}", file=sys.stderr)
        return False


# ─── Collector ──────────────────────────────────────────────────────────────

class SslCollector:
    def __init__(
        self,
        sslsniff_path: str = SSLSNIFF_PATH,
        binary_path: Optional[str] = None,
        pid: Optional[int] = None,
        uid: Optional[int] = None,
        comm: Optional[str] = None,
    ):
        self.sslsniff_path = sslsniff_path
        self.binary_path = binary_path
        self.pid = pid
        self.uid = uid
        self.comm = comm
        self.session_id = str(uuid.uuid4())
        self.capture_start = datetime.now(timezone.utc).isoformat()

    def _build_cmd(self) -> list[str]:
        cmd = [self.sslsniff_path]
        if self.binary_path:
            cmd.extend(["--binary-path", self.binary_path])
        if self.pid:
            cmd.extend(["--pid", str(self.pid)])
        if self.uid:
            cmd.extend(["--uid", str(self.uid)])
        if self.comm and not self.binary_path:
            # --comm doesn't work well with --binary-path (thread name issue)
            cmd.extend(["--comm", self.comm])
        return cmd

    def run_raw(self, webhook_url: Optional[str], output_file: Optional[str],
                batch_size: int = 10, flush_interval: float = 2.0):
        """Run sslsniff and forward raw events."""
        cmd = self._build_cmd()
        print(f"[collector] Starting: {' '.join(cmd)}", file=sys.stderr)
        print(f"[collector] Session: {self.session_id}", file=sys.stderr)

        out_f = open(output_file, "a") if output_file else None
        batch: list[dict] = []
        last_flush = time.time()

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(f"[collector] Skip non-JSON: {line[:80]}", file=sys.stderr)
                    continue

                if out_f:
                    out_f.write(line + "\n")
                    out_f.flush()

                batch.append(event)
                now = time.time()
                if len(batch) >= batch_size or (now - last_flush) >= flush_interval:
                    if webhook_url and batch:
                        payload = {
                            "session_id": self.session_id,
                            "agent": "claude-code",
                            "capture_start": self.capture_start,
                            "events": batch,
                        }
                        ok = send_to_webhook(webhook_url, payload)
                        status = "ok" if ok else "FAIL"
                        print(
                            f"[collector] Sent {len(batch)} events → {status}",
                            file=sys.stderr,
                        )
                    batch = []
                    last_flush = now

        except KeyboardInterrupt:
            print("\n[collector] Interrupted", file=sys.stderr)
        finally:
            # Flush remaining
            if webhook_url and batch:
                payload = {
                    "session_id": self.session_id,
                    "agent": "claude-code",
                    "capture_start": self.capture_start,
                    "events": batch,
                }
                send_to_webhook(webhook_url, payload)
            if out_f:
                out_f.close()
            if proc.poll() is None:
                proc.terminate()

    def run_http(self, webhook_url: Optional[str], output_file: Optional[str],
                 batch_size: int = 5, flush_interval: float = 3.0):
        """Run sslsniff, parse HTTP, and forward interactions."""
        cmd = self._build_cmd()
        print(f"[collector] Starting (HTTP mode): {' '.join(cmd)}", file=sys.stderr)
        print(f"[collector] Session: {self.session_id}", file=sys.stderr)

        out_f = open(output_file, "a") if output_file else None
        # Track pending requests by (pid, tid)
        pending_requests: dict[tuple[int, int], dict] = {}
        batch: list[dict] = []
        last_flush = time.time()

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("is_handshake"):
                    continue

                data = event.get("data")
                if not data:
                    continue

                pid = event.get("pid", 0)
                tid = event.get("tid", 0)
                key = (pid, tid)
                func = event.get("function", "")

                if func == "WRITE/SEND":
                    req = parse_http_request(data)
                    if req:
                        pending_requests[key] = {
                            "timestamp": ns_to_datetime(event.get("timestamp_ns", 0)),
                            "timestamp_ns": event.get("timestamp_ns", 0),
                            "pid": pid,
                            "tid": tid,
                            "uid": event.get("uid", 0),
                            "comm": event.get("comm", ""),
                            "request": req,
                            "request_size": event.get("len", 0),
                            "truncated": event.get("truncated", False),
                        }

                elif func == "READ/RECV":
                    resp = parse_http_response(data)
                    if resp and key in pending_requests:
                        interaction = pending_requests.pop(key)
                        interaction["response"] = resp
                        interaction["response_size"] = event.get("len", 0)
                        if event.get("truncated"):
                            interaction["truncated"] = True
                        # Calculate latency
                        req_ns = interaction.get("timestamp_ns", 0)
                        resp_ns = event.get("timestamp_ns", 0)
                        if req_ns and resp_ns and resp_ns > req_ns:
                            interaction["latency_ms"] = (resp_ns - req_ns) / 1e6

                        if out_f:
                            out_f.write(json.dumps(interaction, default=str) + "\n")
                            out_f.flush()

                        batch.append(interaction)
                        self._print_interaction(interaction)

                now = time.time()
                if len(batch) >= batch_size or (now - last_flush) >= flush_interval:
                    if webhook_url and batch:
                        payload = {
                            "session_id": self.session_id,
                            "agent": "claude-code",
                            "capture_start": self.capture_start,
                            "interactions": batch,
                        }
                        ok = send_to_webhook(webhook_url, payload)
                        status = "ok" if ok else "FAIL"
                        print(
                            f"[collector] Sent {len(batch)} interactions → {status}",
                            file=sys.stderr,
                        )
                    batch = []
                    last_flush = now

        except KeyboardInterrupt:
            print("\n[collector] Interrupted", file=sys.stderr)
        finally:
            if webhook_url and batch:
                payload = {
                    "session_id": self.session_id,
                    "agent": "claude-code",
                    "capture_start": self.capture_start,
                    "interactions": batch,
                }
                send_to_webhook(webhook_url, payload)
            if out_f:
                out_f.close()
            if proc.poll() is None:
                proc.terminate()

    @staticmethod
    def _print_interaction(interaction: dict):
        req = interaction.get("request", {})
        resp = interaction.get("response", {})
        method = req.get("method", "?")
        path = req.get("path", "?")
        status = resp.get("status_code", "?")
        latency = interaction.get("latency_ms", 0)
        print(
            f"[http] {method} {path[:60]} → {status} ({latency:.0f}ms)",
            file=sys.stderr,
        )


# ─── CLI ────────────────────────────────────────────────────────────────────

def find_claude_binary() -> Optional[str]:
    """Auto-detect Claude Code binary path."""
    claude_dir = Path.home() / ".local" / "share" / "claude" / "versions"
    if claude_dir.exists():
        versions = sorted(claude_dir.iterdir(), key=lambda p: p.name, reverse=True)
        for v in versions:
            if v.is_file():
                return str(v)
    return None


def main():
    parser = argparse.ArgumentParser(
        description="eBPF SSL Collector — capture and forward HTTP traffic"
    )
    parser.add_argument(
        "--mode",
        choices=["raw", "http"],
        default="http",
        help="raw: forward raw SSL events; http: parse and forward HTTP interactions",
    )
    parser.add_argument(
        "--webhook",
        type=str,
        default=None,
        help="Webhook URL to forward events to",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file for captured events (JSONL)",
    )
    parser.add_argument(
        "--binary-path",
        type=str,
        default=None,
        help="Path to binary with statically linked SSL (e.g. Claude Code). Auto-detected if not set.",
    )
    parser.add_argument("--pid", type=int, default=None, help="Filter by PID")
    parser.add_argument("--uid", type=int, default=None, help="Filter by UID")
    parser.add_argument("--comm", type=str, default=None, help="Filter by process name")
    parser.add_argument(
        "--sslsniff",
        type=str,
        default=SSLSNIFF_PATH,
        help=f"Path to sslsniff binary (default: {SSLSNIFF_PATH})",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Number of events per webhook batch",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=2.0,
        help="Max seconds between webhook flushes",
    )
    parser.add_argument(
        "--auto-detect-claude",
        action="store_true",
        help="Auto-detect Claude Code binary path",
    )

    args = parser.parse_args()

    if not args.webhook and not args.output:
        print(
            "[collector] Warning: no --webhook or --output specified, "
            "events will only be printed to stderr",
            file=sys.stderr,
        )

    binary_path = args.binary_path
    if not binary_path and args.auto_detect_claude:
        binary_path = find_claude_binary()
        if binary_path:
            print(f"[collector] Auto-detected Claude binary: {binary_path}", file=sys.stderr)
        else:
            print("[collector] Could not auto-detect Claude binary", file=sys.stderr)

    # Verify sslsniff exists
    sslsniff = args.sslsniff
    if not Path(sslsniff).exists():
        print(f"[collector] Error: sslsniff not found at {sslsniff}", file=sys.stderr)
        sys.exit(1)

    collector = SslCollector(
        sslsniff_path=sslsniff,
        binary_path=binary_path,
        pid=args.pid,
        uid=args.uid,
        comm=args.comm,
    )

    if args.mode == "raw":
        collector.run_raw(args.webhook, args.output, args.batch_size, args.flush_interval)
    else:
        collector.run_http(args.webhook, args.output, args.batch_size, args.flush_interval)


if __name__ == "__main__":
    main()
