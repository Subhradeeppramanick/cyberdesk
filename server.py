#!/usr/bin/env python3
"""
server.py - CyberDesk demo web server (standard library only).

Serves the dashboard frontend and a small JSON API:

    GET  /                     -> dashboard
    GET  /static/<file>        -> frontend assets
    GET  /api/stats            -> case counts by category / status / priority
    GET  /api/cases            -> every fictional case
    GET  /api/case?id=CD-...   -> one case with its evidence timeline
    GET  /api/samples          -> fictional sample complaints for the triage demo
    POST /api/triage           -> {"sample_id": "CD-..."} -> category + audit trail + IOCs
                                  (free text is rejected: no real complaints)
    POST /api/analyze          -> {"url": ...}  -> offline heuristic URL report
    GET  /api/ifsc?code=...    -> bank branch lookup (bundled offline sample)

Live DNS/TLS and IFSC lookups are OFF by default. They can be switched on for
local use only with --enable-live-checks (refused unless bound to loopback).

Run:
    python server.py [--port 8000]
Then open http://127.0.0.1:8000
"""

import argparse
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import bankintel
import triage
import urlintel

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(ROOT, "static")
CASES_FILE = os.path.join(ROOT, "data", "cases.json")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


# Runtime options, set in main(). Safe defaults: nothing touches the network.
LIVE_CHECKS = False
RATE_LIMIT = 30          # requests per client per minute on POST endpoints
_hits = {}


def rate_limited(client: str) -> bool:
    now = time.monotonic()
    recent = [t for t in _hits.get(client, []) if now - t < 60]
    recent.append(now)
    _hits[client] = recent
    if len(_hits) > 5000:  # keep memory bounded
        _hits.clear()
    return len(recent) > RATE_LIMIT


def sample_complaints() -> list:
    """Fictional narratives from the bundled case file, offered for triage."""
    return [{"id": c["id"], "title": c["title"], "text": c["narrative"]}
            for c in load_cases()["cases"]]


def load_cases() -> dict:
    with open(CASES_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def build_stats(cases: list) -> dict:
    by_category, by_status, by_priority = {}, {}, {}
    for case in cases:
        by_category[case["category"]] = by_category.get(case["category"], 0) + 1
        by_status[case["status"]] = by_status.get(case["status"], 0) + 1
        by_priority[case["priority"]] = by_priority.get(case["priority"], 0) + 1
    return {
        "total": len(cases),
        "open": sum(1 for c in cases if c["status"] != "Closed"),
        "by_category": by_category,
        "by_status": by_status,
        "by_priority": by_priority,
    }


class CyberDeskHandler(BaseHTTPRequestHandler):
    server_version = "CyberDesk/1.0"

    # -- helpers ----------------------------------------------------------
    def _send_json(self, payload, status=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")

    def _send_file(self, path):
        ext = os.path.splitext(path)[1].lower()
        ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            self._send_json({"error": "not found"}, status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 16 * 1024:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}
        return body if isinstance(body, dict) else {}

    def log_message(self, fmt, *args):  # quieter demo logs
        print(f"  {self.address_string()} - {fmt % args}")

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            return self._send_file(os.path.join(STATIC_DIR, "index.html"))

        if path.startswith("/static/"):
            name = os.path.normpath(path[len("/static/"):])
            if name.startswith("..") or os.path.isabs(name):
                return self._send_json({"error": "bad path"}, status=400)
            return self._send_file(os.path.join(STATIC_DIR, name))

        if path == "/api/stats":
            data = load_cases()
            return self._send_json(build_stats(data["cases"]))

        if path == "/api/cases":
            data = load_cases()
            return self._send_json({
                "fictional": data.get("fictional", True),
                "cases": data["cases"],
            })

        if path == "/api/case":
            case_id = (query.get("id") or [""])[0]
            for case in load_cases()["cases"]:
                if case["id"] == case_id:
                    return self._send_json(case)
            return self._send_json({"error": f"no case {case_id}"}, status=404)

        if path == "/api/samples":
            return self._send_json({"fictional": True, "samples": sample_complaints()})

        if path == "/api/ifsc":
            code = (query.get("code") or [""])[0]
            return self._send_json(bankintel.lookup_ifsc(code, live=LIVE_CHECKS))

        if path == "/api/config":
            return self._send_json({"live_checks": LIVE_CHECKS})

        return self._send_json({"error": "unknown endpoint"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if rate_limited(self.client_address[0]):
            return self._send_json({"error": "too many requests, slow down"}, status=429)
        body = self._read_json_body()

        if parsed.path == "/api/triage":
            if "text" in body:
                return self._send_json(
                    {"error": "This demo only triages the bundled fictional samples. "
                              "Free-text complaints are not accepted; please do not "
                              "submit real complaints or personal data."},
                    status=400)
            sample_id = str(body.get("sample_id") or "")
            sample = next((s for s in sample_complaints() if s["id"] == sample_id), None)
            if sample is None:
                return self._send_json({"error": "send {\"sample_id\": \"CD-...\"} "
                                                 "(see GET /api/samples)"}, status=400)
            text = sample["text"]
            result = triage.categorize(text)
            result["iocs"] = triage.extract_iocs(text)
            return self._send_json(result)

        if parsed.path == "/api/analyze":
            url = (body.get("url") or "").strip()
            if not url:
                return self._send_json({"error": "send {\"url\": \"<url to analyse>\"}"},
                                       status=400)
            return self._send_json(urlintel.analyze_url(url, live=LIVE_CHECKS))

        return self._send_json({"error": "unknown endpoint"}, status=404)


def main():
    parser = argparse.ArgumentParser(description="CyberDesk demo server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--enable-live-checks", action="store_true",
                        help="local use only: enable live DNS/TLS and IFSC lookups")
    args = parser.parse_args()

    global LIVE_CHECKS
    if args.enable_live_checks:
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            parser.error("--enable-live-checks is only allowed when bound to loopback")
        LIVE_CHECKS = True

    server = ThreadingHTTPServer((args.host, args.port), CyberDeskHandler)
    print(f"CyberDesk demo running at http://{args.host}:{args.port}")
    print("All case data is fictional. Live network checks: "
          + ("ON (local only)" if LIVE_CHECKS else "OFF (offline demo mode)"))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
