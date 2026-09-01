# web_console.py - tiny local console (loopback only, simulation only)
# P1: Added rate limiting and improved security headers
import html
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import authentication
import config
import device_simulator
import reset_workflow
import security_logger

PAGE = """<html>
<head><title>Android Reset Lab - Simulation Only</title></head>
<body style="font-family:monospace; background:#111; color:#7f6">
<h2>ANDROID RESET LAB - SIMULATION ONLY</h2>
<p style="color:#fa0">Local-only demo. No real devices touched. Credentials are simulation-only.</p>
<form method="post" action="/request">
  user: <input name="user"><br>
  pass: <input name="pass" type="password"><br>
  device: <input name="device" value="AND-003"><br>
  <button>Request reset</button>
</form>
<pre>{msg}</pre>
</body>
</html>"""

# P1: Simple in-memory rate limiting per IP
rate_limit_store = defaultdict(deque)  # ip -> deque of timestamps

def is_rate_limited(ip):
    """Check if IP is rate limited. Returns True if limited, False otherwise."""
    now = time.time()
    window_start = now - config.RATE_LIMIT_WINDOW_SECONDS
    
    # Clean old entries
    dq = rate_limit_store[ip]
    while dq and dq[0] < window_start:
        dq.popleft()
    
    # Check if over limit
    if len(dq) >= config.RATE_LIMIT_REQUESTS:
        return True
    
    # Add current request
    dq.append(now)
    return False


class Handler(BaseHTTPRequestHandler):
    def _page(self, msg="", status=200):
        # Fix: HTML escape msg to prevent XSS
        safe_msg = html.escape(msg)
        body = PAGE.replace("{msg}", safe_msg).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress default logging or use security_logger if needed
        return

    def do_GET(self):
        self._page()

    def do_POST(self):
        client_ip = self.client_address[0]
        
        # P1: Rate limiting check
        if is_rate_limited(client_ip):
            security_logger.log_event("RATE_LIMITED", client_ip, "web console rate limit exceeded", severity="WARNING")
            self._page("Too many requests. Please wait a minute and try again.", status=429)
            return

        length = int(self.headers.get("Content-Length", 0))
        # Limit request size to prevent DoS
        if length > 4096:
            self._page("Request too large", status=413)
            return
            
        try:
            form = parse_qs(self.rfile.read(length).decode('utf-8', errors='ignore'))
        except Exception:
            self._page("Invalid request", status=400)
            return
            
        user = form.get("user", [""])[0].strip()[:64]  # Limit length
        password = form.get("pass", [""])[0][:128]
        device = form.get("device", [""])[0].strip()[:20]

        # Basic input validation
        if not user or not password or not device:
            self._page("Missing required fields")
            return

        ok, msg = authentication.login(user, password)
        if not ok:
            security_logger.log_event("LOGIN_FAILED", user, f"web console: {msg}", severity="WARNING", device_id=device)
            self._page("login failed: " + msg)
            return
        
        # Log successful login
        security_logger.log_event("LOGIN_SUCCESS", user, "web console login", severity="INFO", device_id=device)
        
        token = authentication.start_session(user)
        ok, info = reset_workflow.request_reset(token, device)
        if ok:
            self._page("request created: " + info +
                       "\nA SECOND account must approve in the terminal:\n"
                       f"python approve_helper.py {info}")
        else:
            self._page("request denied: " + info)


if __name__ == "__main__":
    device_simulator.seed_devices()
    server = HTTPServer(("127.0.0.1", 8000), Handler)
    print("console on http://127.0.0.1:8000 - Ctrl+C stops it")
    server.serve_forever()