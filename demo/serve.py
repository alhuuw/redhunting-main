#!/usr/bin/env python3
"""demo serve: a stdlib-only vulnerable app for offline regression of the redhunting loop.

Binds 127.0.0.1 only. Planted surfaces (deliberately trivial, they exist to exercise
the pipeline, not to model real bugs):
  GET  /                      liveness
  GET  /api/orders/<n>        unauthenticated object read, sequential ids 1001..1010, PII fields
  GET  /api/me                401 without a valid bearer (negative-control surface)
  GET  /debug/config          hardcoded fake key (secret-sweep lead source)
  GET  /redirect?url=         open redirect (chain-fodder lead source)

Usage: python3 demo/serve.py [port]     (default 18765)
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ORDERS = {
    1001 + i: {
        "order_id": 1001 + i,
        "customer_name": f"Customer {i:02d}",
        "address": f"Jl. Test No. {i}",
        "phone": f"+6280000000{i:02d}",
        "total": 1000 + i,
        "created_at": f"2026-09-0{i % 9 + 1}T10:00:00Z",
    }
    for i in range(10)
}

VALID_TOKEN = "demo-bearer-token"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        u = urlparse(self.path)

        if u.path == "/":
            self._send(200, {"ok": True, "service": "redhunting-demo"})
            return

        if u.path.startswith("/api/orders/"):
            tail = u.path.rsplit("/", 1)[-1]
            if not tail.isdigit():
                self._send(400, {"error": "invalid order id"})
                return
            order = ORDERS.get(int(tail))
            if order is None:
                self._send(404, {"error": "order not found"})
                return
            self._send(200, order)
            return

        if u.path == "/api/me":
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {VALID_TOKEN}":
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"user": "demo", "email": "demo@localhost"})
            return

        if u.path == "/debug/config":
            self._send(200, {"payment_api_key": "sk_live_DEMOKEY00000000001111", "env": "prod"})
            return

        if u.path == "/redirect":
            target = parse_qs(u.query).get("url", [""])[0]
            if target.startswith("http://") or target.startswith("https://"):
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return
            self._send(400, {"error": "missing url param"})
            return

        self._send(404, {"error": "not found"})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18765
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"demo serving on http://127.0.0.1:{port} (ctrl-c to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
