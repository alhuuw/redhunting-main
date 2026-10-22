#!/usr/bin/env python3
"""rh_capture: the single front door for capturing proof in a hunt.

Every dynamic probe goes through this tool so evidence is always a tool-generated
raw transcript (config.json capture.transcripts_tool_generated_only). Hand-written
or AI-summarized evidence files are banned as proof; this tool makes them
unnecessary. curl -v / mitmproxy exports are the documented fallback for surfaces
this tool cannot reach (TLS-fingerprint WAFs, HTTP/2-only hosts) - never retype.

Usage:
  python3 bin/rh_capture.py <target> <slug> <method> <url> \
      [--header 'K: V']... [--data '...'] [--tag slug] [--note '...'] [--timeout 25]

Writes into targets/<target>/findings/<slug>/evidence/raw/:
  <slug>_<tag>.txt   full raw transcript (request as sent, response as received, UTC)
  <slug>_<tag>.bin   byte-exact body when the response is binary
  SHA256SUMS.txt           regenerated over every raw file

Exit codes: 0 captured; 2 usage error; 3 network/HTTP error (recorded in transcript).
"""
import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
CTX = ssl.create_default_context()


def parse_header(s):
    if ":" not in s:
        raise argparse.ArgumentTypeError(f"header must be 'K: V', got: {s}")
    k, v = s.split(":", 1)
    return k.strip(), v.strip()


def prog_dir(target: str) -> Path:
    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    env_key = cfg.get("workspace", {}).get("env_override", "RH_HOME")
    root = (os.environ.get(env_key) if env_key else None) or cfg.get("workspace", {}).get("root", "./")
    base = Path.cwd() if root in (".", "./") else Path(os.path.expanduser(root))
    return base / target


def capture(scheme, host, port, method, path, headers, body, timeout):
    if scheme == "http":
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(host, port, context=CTX, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.reason, resp.getheaders(), resp.read()
    except Exception as e:
        return "ERR", f"{type(e).__name__}: {e}"[:200], [], b""
    finally:
        conn.close()


def render_transcript(fname, note, ts_req, method, scheme, host, path, headers, body_bytes,
                      ts_resp, status, reason, resp_headers, resp_body, bin_relpath):
    lines = [
        f"CAPTURE TIME (UTC): {ts_req}",
        "TOOL: rh_capture.py (raw transcript; no manual edits)",
        f"NOTE: {note}" if note else "",
        "=== REQUEST (exactly as sent) ===",
        f"{method} {scheme}://{host}{path} HTTP/1.1",
        f"Host: {host}",
    ]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    if body_bytes:
        lines += ["", "[request body] " + body_bytes.decode("utf-8", "replace")]
    lines += ["", f"=== RESPONSE (exactly as received, {ts_resp}) ===",
              f"HTTP/1.1 {status} {reason}"]
    lines += [f"{k}: {v}" for k, v in resp_headers]
    lines += [""]
    is_binary = any(b > 0x7e or (b < 0x20 and b not in (0x09, 0x0a, 0x0d)) for b in resp_body[:512])
    if is_binary and resp_body:
        lines += [
            f"[response body: BINARY, {len(resp_body)} bytes, saved byte-exact to {bin_relpath}]",
            f"[sha256 of body: {hashlib.sha256(resp_body).hexdigest()}]",
            "[first 256 bytes as hex dump]",
        ]
        hexhead = resp_body[:256].hex(" ")
        lines += ["  " + hexhead[i:i + 96] for i in range(0, len(hexhead), 96)]
    else:
        lines += ["[response body, verbatim]", resp_body.decode("utf-8", "replace")]
    lines += ["", f"[body sha256: {hashlib.sha256(resp_body).hexdigest()}]"]
    return "\n".join(lines) + "\n"


def evidence_envelope(fname, note, target, slug, method, url, status, resp_body,
                      started_at, ended_at, bin_rel, is_binary, manifest_ref):
    """REA-pattern evidence envelope: machine-readable sidecar with artifact identity,
    request identity, integrity, and EXPLICIT limitation. A capture that cannot answer
    the question it was fired for says so here instead of implying it."""
    return {
        "schema": "redhunting.evidence/1",
        "id": fname,
        "captured_at": started_at,
        "completed_at": ended_at,
        "tool": "rh_capture.py",
        "target": {"slug": target, "finding": slug, "url": url, "method": method},
        "artifact": {
            "transcript": fname + ".txt",
            "binary": bin_rel if (is_binary and resp_body) else None,
            "sha256": hashlib.sha256(resp_body).hexdigest(),
            "bytes": len(resp_body),
        },
        "integrity": {"transcript_generated_by_tool": True, "manual_edits_detected": None},
        "status": status,
        "manifest": manifest_ref,
        "note": note,
        "LIMITATIONS": [
            "transcript records exactly one request/response pair; repetition, ordering, and cache behavior are NOT established by this artifact",
            "conclusions drawn from this capture must be re-verified at claim time by the verify ladders; correlation here is not causation",
        ],
    }


def write_envelope(fdir, raw_dir, envelope):
    import json as _json
    p = raw_dir / (envelope["id"] + ".evidence.json")
    p.write_text(_json.dumps(envelope, indent=2) + "\n")
    return p


def main():
    ap = argparse.ArgumentParser(description="Raw evidence capture front door")
    ap.add_argument("target")
    ap.add_argument("slug")
    ap.add_argument("method", choices=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    ap.add_argument("url")
    ap.add_argument("--header", type=parse_header, action="append", default=[])
    ap.add_argument("--data", default=None, help="request body (string)")
    ap.add_argument("--tag", default="probe", help="slug for the filename")
    ap.add_argument("--note", default="")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--pacing", type=float, default=None, help="sleep after capture (seconds; default from config pacing)")
    a = ap.parse_args()

    u = urllib.parse.urlsplit(a.url)
    if u.scheme not in ("http", "https"):
        print("URL must be http or https", file=sys.stderr)
        return 2
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path + (("?" + u.query) if u.query else "")

    headers = dict(a.header)
    body = a.data.encode() if a.data is not None else None
    if body is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    if body is not None and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))

    fdir = prog_dir(a.target) / "findings" / a.slug
    raw_dir = fdir / "evidence" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    fname = re.sub(r"[^A-Za-z0-9_-]+", "_", f"{a.slug}_{a.tag}")
    txt_path = raw_dir / (fname + ".txt")
    bin_path = raw_dir / (fname + ".bin")

    cfg = json.loads((SKILL_DIR / "config.json").read_text())
    if a.pacing is None:
        a.pacing = cfg.get("pacing", {}).get("delay_ms", 150) / 1000.0

    ts_req = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    status, reason, resp_headers, resp_body = capture(u.scheme, host, port, a.method, path, headers, body, a.timeout)
    ts_resp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    hostport = f"{host}:{port}" if port not in (80, 443) else host

    is_binary = any(b > 0x7e or (b < 0x20 and b not in (0x09, 0x0a, 0x0d)) for b in resp_body[:512])
    bin_rel = fname + ".bin"
    if is_binary and resp_body:
        bin_path.write_bytes(resp_body)
    transcript = render_transcript(fname, a.note, ts_req, a.method, u.scheme, hostport, path,
                                   headers, body or b"", ts_resp, status, reason, resp_headers,
                                   resp_body, bin_rel)
    txt_path.write_text(transcript)

    envelope = evidence_envelope(fname, a.note, a.target, a.slug, a.method, a.url, status,
                                 resp_body, ts_req, ts_resp, bin_rel, is_binary,
                                 {"sha256sums": "SHA256SUMS.txt", "raw_dir_rel": str(raw_dir.relative_to(fdir))})
    write_envelope(fdir, raw_dir, envelope)

    sums = raw_dir / "SHA256SUMS.txt"
    hash_lines = []
    for fn in sorted(os.listdir(raw_dir)):
        if fn == "SHA256SUMS.txt" or fn.startswith("."):
            continue
        hash_lines.append(f"{hashlib.sha256((raw_dir / fn).read_bytes()).hexdigest()}  {fn}")
    sums.write_text("\n".join(hash_lines) + "\n")

    print(f"[{fname}] HTTP {status} {len(resp_body)}B -> {txt_path.name}" + (f" + {bin_rel}" if is_binary and resp_body else ""))
    if a.pacing:
        time.sleep(a.pacing)
    return 0 if status != "ERR" else 3


if __name__ == "__main__":
    sys.exit(main())
