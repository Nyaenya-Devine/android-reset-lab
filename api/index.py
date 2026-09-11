"""Vercel serverless entrypoint for the Android Reset Lab web console.

The console is a simulation-only, stdlib HTTP application. Vercel cannot run
a long-lived socket server, so this module re-hosts the existing
``web_console.Handler`` (unchanged) behind the WSGI interface with an
in-memory socket shim. Lab state (users, devices, audit logs) lives under
/tmp — the only writable directory on Vercel — and is re-seeded on cold
starts, which suits a self-contained simulation demo.

Note: this file intentionally avoids subprocess/shutil/eval and
destructive-call names so the repo's own AST safety tests keep passing.
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# --- Route lab file I/O into /tmp (Vercel's only writable directory) ------
_TMP = "/tmp/android-reset-lab"  # nosec B108 - Vercel requires /tmp, not configurable
os.makedirs(os.path.join(_TMP, "logs"), exist_ok=True)
os.makedirs(os.path.join(_TMP, "data"), exist_ok=True)

_orig_makedirs = os.makedirs


def _tmp_makedirs(name, mode=0o777, exist_ok=False):
    # Several lab modules mkdir relative dirs like "logs"/"data" against the
    # working directory, which is read-only on Vercel. Redirect relative
    # targets under /tmp; leave absolute paths untouched.
    if not os.path.isabs(name):
        name = os.path.join(_TMP, name)
    return _orig_makedirs(name, mode=mode, exist_ok=exist_ok)


os.makedirs = _tmp_makedirs

import config  # noqa: E402

config.LOG_FILE = os.path.join(_TMP, "logs", "security_log.jsonl")
config.HMAC_KEY_FILE = os.path.join(_TMP, "data", "hmac.key")
config.STORAGE_DB = os.path.join(_TMP, "data", "lab.db")

import authentication  # noqa: E402
import device_simulator  # noqa: E402
import reset_workflow  # noqa: E402

authentication.USERS_FILE = os.path.join(_TMP, "data", "users.json")
authentication.SESSIONS_FILE = os.path.join(_TMP, "data", "sessions.json")
device_simulator.DEVICES_FILE = os.path.join(_TMP, "data", "devices.json")
reset_workflow.REQUESTS_FILE = os.path.join(_TMP, "data", "requests.json")

import seed_lab  # noqa: E402
import web_console  # noqa: E402

# Seed the demo fleet + accounts once per cold start (idempotent). If this
# ever fails we still boot, but the traceback shows up in function logs.
try:
    seed_lab.seed_all()
except Exception:
    import traceback
    traceback.print_exc()


class _Capture(io.IOBase):
    """Write-only buffer that keeps its bytes even after close()."""

    def __init__(self):
        self._buf = bytearray()

    def write(self, data):
        self._buf += data
        return len(data)

    def getvalue(self):
        return bytes(self._buf)


class _ShimSocket:
    """Minimal TCP-socket stand-in for BaseHTTPRequestHandler."""

    def __init__(self, request_bytes):
        self._r = io.BytesIO(request_bytes)
        self._w = _Capture()

    def makefile(self, mode, *args, **kwargs):
        if mode.startswith("r"):
            return self._r
        return self._w

    def getsockname(self):
        return ("127.0.0.1", 0)

    def sendall(self, data):
        # Python 3.13's StreamRequestHandler writes via _SocketWriter, which
        # calls socket.sendall directly.
        self._w.write(data)

    def close(self):
        return None

    def shutdown(self, *_):
        return None

    def response_bytes(self):
        return self._w.getvalue()


def _parse_response(raw):
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return 500, [], b""
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    code = 500
    reason = "Internal Server Error"
    try:
        code = int(parts[1])
        reason = parts[2].decode("utf-8", "replace") if len(parts) > 2 else ""
    except (IndexError, ValueError):
        pass
    headers = []
    for line in lines[1:]:
        if b":" in line:
            key, _, value = line.partition(b":")
            headers.append((key.decode("utf-8", "replace").strip(),
                            value.decode("utf-8", "replace").strip()))
    return code, headers, body


def _serve_request(method, raw_path, headers, body, client_ip):
    lines = [f"{method} {raw_path} HTTP/1.1",
             "Host: android-reset-lab.vercel.app",
             "Connection: close"]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    for key, value in headers:
        lines.append(f"{key}: {value}")
    request_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
    sock = _ShimSocket(request_bytes)
    try:
        web_console.Handler(sock, (client_ip, 0), None)
    except Exception:
        import traceback
        traceback.print_exc()
    return _parse_response(sock.response_bytes())


def app(environ, start_response):
    method = (environ.get("REQUEST_METHOD") or "GET").upper()
    path = environ.get("PATH_INFO") or "/"
    query = environ.get("QUERY_STRING") or ""
    raw_path = path + ("?" + query if query else "")
    headers = []
    cookie = environ.get("HTTP_COOKIE")
    if cookie:
        headers.append(("Cookie", cookie))
    body = b""
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if length > 0:
            body = environ["wsgi.input"].read(length)
    except (ValueError, KeyError):
        body = b""
    if method == "POST":
        content_type = environ.get("CONTENT_TYPE") or "application/x-www-form-urlencoded"
        headers.append(("Content-Type", content_type))
    forwarded = environ.get("HTTP_X_FORWARDED_FOR") or ""
    client_ip = (forwarded.split(",")[0].strip()
                 or environ.get("REMOTE_ADDR") or "127.0.0.1")
    code, resp_headers, resp_body = _serve_request(
        method, raw_path, headers, body, client_ip)
    reason = "OK" if 200 <= code < 300 else ("Found" if code == 302 else "Error")
    status = f"{code} {reason}"
    start_response(status, resp_headers)
    return [resp_body]
