# web_console.py - tiny local console (loopback only, simulation only)
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import authentication
import device_simulator
import reset_workflow

PAGE = """<html>
<body style="font-family:monospace; background:#111; color:#7f6">
<h2>ANDROID RESET LAB - SIMULATION ONLY</h2>
<form method="post" action="/request">
  user: <input name="user"><br>
  pass: <input name="pass" type="password"><br>
  device: <input name="device" value="AND-003"><br>
  <button>Request reset</button>
</form>
<pre>{msg}</pre>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _page(self, msg=""):
        body = PAGE.replace("{msg}", msg).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._page()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        user = form.get("user", [""])[0]
        password = form.get("pass", [""])[0]
        device = form.get("device", [""])[0]
        ok, msg = authentication.login(user, password)
        if not ok:
            self._page("login failed: " + msg)
            return
        token = authentication.start_session(user)
        ok, info = reset_workflow.request_reset(token, device)
        if ok:
            self._page("request created: " + info +
                       "\nA SECOND account must approve in the terminal:")
        else:
            self._page("request denied: " + info)


if __name__ == "__main__":
    device_simulator.seed_devices()
    server = HTTPServer(("127.0.0.1", 8000), Handler)
    print("console on http://127.0.0.1:8000 - Ctrl+C stops it")
    server.serve_forever()