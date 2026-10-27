"""Small dependency-free HTTP API for the portable LogScope analyzer."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import json
import math
import ipaddress
import os
import subprocess
import tempfile
from analyzer import analyze

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "cpp_engine" / ("engine.exe" if os.name == "nt" else "engine")
WEB = ROOT / "frontend"
report_cache = None

class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, code, data, content_type):
        self.send_response(code); self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data))); self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers(); self.wfile.write(data)

    def send_json(self, code, value):
        self.send_bytes(code, json.dumps(value).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        global report_cache
        url = urlparse(self.path)
        if url.path == "/api/health":
            self.send_json(200, {"ok": True, "cppEngineIncluded": (ROOT / "cpp_engine" / "main.cpp").is_file(),
                                 "cppExecutablePresent": ENGINE.is_file(), "fallbackAvailable": True}); return
        if url.path == "/api/ip":
            if not report_cache:
                self.send_json(409, {"error": "Upload and analyze a log first."}); return
            ip = parse_qs(url.query).get("ip", [""])[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                self.send_json(400, {"error": "Enter a valid IPv4 or IPv6 address."}); return
            details = next((x for x in report_cache["ips"] if x["ip"] == ip), None)
            if details is None:
                self.send_json(404, {"error": "This IP was not present in the analyzed log."}); return
            details = dict(details)
            details["findings"] = [f for f in report_cache["findings"] if f["ip"] == ip]
            self.send_json(200, details); return
        if url.path.startswith("/api/"):
            self.send_json(404, {"error": "Unknown API endpoint."}); return
        relative = "index.html" if url.path == "/" else url.path.lstrip("/")
        path = (WEB / relative).resolve()
        if WEB.resolve() not in path.parents and path != WEB.resolve():
            self.send_json(404, {"error": "Not found."}); return
        if not path.is_file():
            self.send_json(404, {"error": "Not found."}); return
        typ = "text/html; charset=utf-8" if path.suffix == ".html" else "text/" + ("css" if path.suffix == ".css" else "javascript") + "; charset=utf-8"
        self.send_bytes(200, path.read_bytes(), typ)

    def do_POST(self):
        global report_cache
        if self.path != "/api/analyze":
            self.send_json(404, {"error": "Unknown API endpoint."}); return
        try:
            ctype = self.headers.get("Content-Type", "")
            if not ctype.lower().startswith("multipart/form-data"):
                self.send_json(400, {"error": "Send a multipart form with a log file."}); return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 10 * 1024 * 1024:
                self.send_json(413, {"error": "Upload must be between 1 byte and 10 MB."}); return
            body = self.rfile.read(length)
            msg = BytesParser(policy=default).parsebytes((f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
            fields = {}
            for part in msg.iter_parts():
                disposition = part.get_content_disposition()
                name = part.get_param("name", header="content-disposition")
                if disposition == "form-data" and name:
                    fields[name] = (part.get_filename(), part.get_payload(decode=True) or b"")
            if "file" not in fields or not fields["file"][0]:
                self.send_json(400, {"error": "Choose a log file to upload."}); return
            filename, payload = fields["file"]
            if Path(filename).suffix.lower() not in {".log", ".txt"}:
                self.send_json(400, {"error": "Upload a .log or .txt access-log file."}); return
            if len(payload) > 10 * 1024 * 1024 or b"\x00" in payload:
                self.send_json(400, {"error": "File is too large or is not plain text."}); return
            try:
                payload.decode("utf-8")
            except UnicodeDecodeError:
                self.send_json(400, {"error": "Log file must be UTF-8 plain text."}); return
            def value(key, default):
                raw = fields.get(key, (None, str(default).encode()))[1].decode("utf-8").strip()
                return raw
            fail, window, rps = int(value("failThreshold", 10)), int(value("windowSeconds", 300)), float(value("rpsThreshold", 5))
            if not (1 <= fail <= 1000000 and 1 <= window <= 86400 and math.isfinite(rps) and 0 < rps <= 1000000):
                raise ValueError("Thresholds are outside allowed limits.")
            if not payload.strip():
                self.send_json(422, {"error": "The uploaded log is empty."}); return
            report_cache = None
            if ENGINE.is_file():
                temp_path = None
                try:
                    with tempfile.NamedTemporaryFile(prefix="log-analysis-", suffix=".log", delete=False) as tmp:
                        tmp.write(payload)
                        temp_path = tmp.name
                    run = subprocess.run([str(ENGINE), temp_path, str(fail), str(window), str(rps)],
                                         capture_output=True, text=True, timeout=30, check=False)
                    if run.returncode == 0:
                        report_cache = json.loads(run.stdout)
                except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                    # An incompatible or stale native binary should not prevent local analysis.
                    report_cache = None
                finally:
                    if temp_path:
                        Path(temp_path).unlink(missing_ok=True)
            engine_used = "cpp" if report_cache is not None else "python"
            if report_cache is None:
                report_cache = analyze(payload.decode("utf-8"), fail, window, rps)
            report_cache["engine"] = engine_used
            report_cache["filename"] = Path(filename).name[:120]
            self.send_json(200, report_cache)
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_json(400, {"error": str(exc) or "Invalid request values."})
        except Exception:
            self.send_json(500, {"error": "Analysis failed unexpectedly."})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 5000), Handler)
    print("LogScope: http://127.0.0.1:5000")
    print("C++ source: %s" % ((ROOT / "cpp_engine" / "main.cpp").is_file() and "included" or "missing"))
    print("Analysis: C++ engine when compatible; Python fallback otherwise")
    server.serve_forever()
