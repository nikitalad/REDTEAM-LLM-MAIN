"""
mock-egress/server.py

Captures ALL inbound HTTP requests and logs them as
potential exfiltration attempts.

Endpoints:
  GET  /ping          — health check
  GET  /egress/stream — SSE stream of live egress hits (requires Redis)
  ANY  /*             — capture + log everything else

Set RESULT_BACKEND=redis and REDIS_URL to enable pub/sub and SSE.
"""

import json
import os
import pathlib
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_DIR  = pathlib.Path("/app/log")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "egress_attempts.jsonl"

# ── Optional Redis pub/sub ────────────────────────────────────────────────────

_redis_client = None

def _init_redis():
    global _redis_client
    if os.environ.get("RESULT_BACKEND", "jsonl").lower() != "redis":
        return
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = redis.from_url(url, decode_responses=True)
        _redis_client.ping()
        print(f"[pub/sub] Redis connected at {url}", flush=True)
    except Exception as e:
        print(f"[pub/sub] Redis unavailable — pub/sub disabled: {e}", flush=True)
        _redis_client = None


def _publish(record: dict) -> None:
    if _redis_client is None:
        return
    try:
        _redis_client.publish("egress:stream", json.dumps(record))
    except Exception:
        pass


# ── SSE subscriber thread ─────────────────────────────────────────────────────

class _SSEHandler:
    """Manage a set of open SSE connections and fan-out published events."""

    def __init__(self):
        self._lock    = threading.Lock()
        self._clients: list = []

    def add(self, wfile):
        with self._lock:
            self._clients.append(wfile)

    def remove(self, wfile):
        with self._lock:
            self._clients = [c for c in self._clients if c is not wfile]

    def broadcast(self, data: str):
        msg = f"data: {data}\n\n".encode()
        with self._lock:
            dead = []
            for wfile in self._clients:
                try:
                    wfile.write(msg)
                    wfile.flush()
                except Exception:
                    dead.append(wfile)
            for d in dead:
                self._clients.remove(d)


_sse = _SSEHandler()


def _redis_subscriber_thread():
    """Background thread: subscribe to egress:stream and broadcast to SSE clients."""
    if _redis_client is None:
        return
    try:
        import redis
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        sub_client = redis.from_url(url, decode_responses=True)
        pubsub = sub_client.pubsub()
        pubsub.subscribe("egress:stream")
        for message in pubsub.listen():
            if message["type"] == "message":
                _sse.broadcast(message["data"])
    except Exception as e:
        print(f"[pub/sub] subscriber thread error: {e}", flush=True)


# ── HTTP handler ──────────────────────────────────────────────────────────────

class EgressHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/ping":
            self._respond(200, {"status": "ok"})
            return
        if self.path == "/egress/stream":
            self._handle_sse()
            return
        self._capture_and_respond()

    def do_POST(self):
        self._capture_and_respond()

    def do_PUT(self):
        self._capture_and_respond()

    def _capture_and_respond(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method":    self.command,
            "path":      self.path,
            "client":    self.client_address[0],
            "headers":   dict(self.headers),
            "body":      body,
            "body_len":  len(body),
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")

        _publish(record)

        print(f"[CAPTURED] {self.command} {self.path}  body_len={len(body)}", flush=True)
        self._respond(200, {"status": "captured", "body_len": len(body)})

    def _handle_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection",    "keep-alive")
        self.end_headers()
        _sse.add(self.wfile)
        try:
            # Block until client disconnects
            while True:
                self.rfile.read(1)
        except Exception:
            pass
        finally:
            _sse.remove(self.wfile)

    def _respond(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _init_redis()
    if _redis_client is not None:
        t = threading.Thread(target=_redis_subscriber_thread, daemon=True)
        t.start()
    server = HTTPServer(("0.0.0.0", 9999), EgressHandler)
    print("Mock egress server listening on :9999", flush=True)
    server.serve_forever()
