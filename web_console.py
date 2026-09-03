"""Local, simulation-only web console.

The console intentionally keeps all policy decisions in the existing
authentication, authorization, and reset workflow modules.  This module is
only the presentation and HTTP transport layer.
"""

import html
import time
from collections import Counter, defaultdict, deque
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import authentication
import authorization
import config
import device_simulator
import reset_workflow
import security_logger
import threat_detection


MAX_REQUEST_BYTES = 4096
SESSION_COOKIE = "session"

STYLE = """
:root {
  color-scheme: dark;
  --ink: #eef4ff;
  --muted: #98a8c0;
  --line: #26344b;
  --panel: #111c2e;
  --panel-strong: #16243a;
  --canvas: #08111f;
  --accent: #5eead4;
  --accent-strong: #2dd4bf;
  --warning: #fbbf24;
  --danger: #fb7185;
  --good: #86efac;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-width: 320px;
  overflow-x: hidden;
  color: var(--ink);
  background:
    radial-gradient(circle at 85% -10%, #183d55 0, transparent 34rem),
    var(--canvas);
  line-height: 1.5;
}
a { color: var(--accent); }
button, input, select { font: inherit; }
.shell { width: min(1180px, calc(100% - 40px)); margin: 0 auto; }
.topbar {
  border-bottom: 1px solid var(--line);
  background: rgba(8, 17, 31, .88);
  backdrop-filter: blur(12px);
}
.topbar-inner {
  display: flex; align-items: center; justify-content: space-between;
  gap: 20px; min-height: 76px;
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand > div:last-child { min-width: 0; }
.brand-mark {
  display: grid; place-items: center; width: 38px; height: 38px;
  color: #06221f; background: var(--accent); border-radius: 12px;
  font-weight: 900;
}
.brand-title { font-weight: 800; letter-spacing: -.02em; }
.brand-subtitle { color: var(--muted); font-size: .78rem; }
.userbar { display: flex; align-items: center; gap: 14px; color: var(--muted); font-size: .9rem; }
.userbar strong { color: var(--ink); }
.eyebrow { color: var(--accent); text-transform: uppercase; letter-spacing: .16em; font-size: .72rem; font-weight: 800; }
h1, h2, h3, p { margin-top: 0; }
h1 { font-size: clamp(2rem, 5vw, 3.5rem); line-height: 1.05; letter-spacing: -.045em; margin-bottom: 18px; }
h2 { font-size: 1.15rem; margin-bottom: 4px; }
h3 { font-size: .98rem; margin-bottom: 3px; }
.muted { color: var(--muted); }
.small { font-size: .82rem; }
.main { padding: 48px 0 72px; }
.hero { max-width: 720px; margin-bottom: 30px; }
.hero p { color: var(--muted); max-width: 650px; font-size: 1.05rem; }
.notice {
  padding: 12px 14px; border: 1px solid #31506b; border-radius: 10px;
  color: #cbe8f4; background: #10283a; margin: 18px 0;
}
.notice.warning { color: #fde68a; border-color: #715a1d; background: #2b2411; }
.notice.error { color: #fecdd3; border-color: #713548; background: #301622; }
.grid { display: grid; gap: 16px; }
.stats { grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 22px 0; }
.two-col { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.card {
  padding: 21px; border: 1px solid var(--line); border-radius: 16px;
  background: linear-gradient(145deg, rgba(22,36,58,.96), rgba(14,25,42,.96));
  box-shadow: 0 14px 35px rgba(0,0,0,.16);
}
.stat-label { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .1em; }
.stat-value { font-size: 1.9rem; font-weight: 800; margin-top: 7px; }
.stat-detail { color: var(--muted); font-size: .8rem; margin-top: 4px; }
.section-head { display: flex; align-items: end; justify-content: space-between; gap: 15px; margin: 30px 0 12px; }
.section-head h2 { margin: 0; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
th { color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 700; }
td { color: #dce7f7; }
tr:last-child td { border-bottom: 0; }
.pill {
  display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 99px;
  border: 1px solid var(--line); color: var(--muted); font-size: .74rem; font-weight: 700;
}
.pill.good { color: var(--good); border-color: #276344; background: #10291e; }
.pill.warning { color: var(--warning); border-color: #715a1d; background: #2b2411; }
.pill.danger { color: var(--danger); border-color: #713548; background: #301622; }
.pill.info { color: var(--accent); border-color: #21645d; background: #102c2a; }
.bars { display: grid; gap: 13px; margin-top: 17px; }
.bar-line { display: grid; grid-template-columns: 84px 1fr 30px; align-items: center; gap: 10px; font-size: .82rem; }
.bar-track { height: 8px; overflow: hidden; border-radius: 99px; background: #203049; }
.bar-fill { height: 100%; min-width: 2px; border-radius: inherit; background: var(--accent-strong); }
.bar-fill.warning { background: var(--warning); }
.bar-fill.danger { background: var(--danger); }
.rule-list { display: grid; gap: 8px; margin-top: 15px; }
.rule-item { display: flex; justify-content: space-between; gap: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
.rule-item:last-child { border-bottom: 0; padding-bottom: 0; }
.form-card { max-width: 620px; }
label { display: block; color: var(--muted); font-size: .82rem; font-weight: 700; margin: 14px 0 6px; }
input, select {
  width: 100%; padding: 11px 12px; color: var(--ink); background: #0b1728;
  border: 1px solid #31435e; border-radius: 9px; outline: none;
}
input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(94,234,212,.13); }
.password-control { position: relative; }
.password-control input[type="text"] { display: none; }
.password-control input[type="checkbox"] { position: absolute; opacity: 0; pointer-events: none; }
.password-control input[type="checkbox"]:checked ~ input[type="password"] { display: none; }
.password-control input[type="checkbox"]:checked ~ input[type="text"] { display: block; }
.password-toggle { display: inline-flex; align-items: center; gap: 7px; margin: 9px 0 0; color: var(--muted); font-size: .78rem; cursor: pointer; }
.password-toggle::before { content: ""; width: 15px; height: 15px; border: 1px solid #526683; border-radius: 4px; background: #0b1728; }
.password-control input[type="checkbox"]:focus-visible + .password-toggle::before { outline: 2px solid var(--accent); outline-offset: 2px; }
.password-control input[type="checkbox"]:checked + .password-toggle::before { background: var(--accent); box-shadow: inset 0 0 0 3px #0b1728; }
button {
  cursor: pointer; border: 0; border-radius: 9px; padding: 11px 16px;
  color: #06221f; background: var(--accent); font-weight: 800; margin-top: 18px;
}
button:hover { background: #99f6e4; }
.button-secondary { color: var(--ink); background: transparent; border: 1px solid #415473; margin: 0; }
.button-secondary:hover { background: #182942; }
.footer { color: var(--muted); border-top: 1px solid var(--line); padding: 20px 0; font-size: .78rem; }
.login-layout { display: grid; grid-template-columns: 1.1fr .9fr; align-items: center; gap: 70px; min-height: calc(100vh - 130px); }
.login-card { max-width: 470px; }
.login-card .card { padding: 32px; }
.security-list { display: grid; gap: 13px; margin: 28px 0 0; padding: 0; list-style: none; }
.security-list li { display: flex; gap: 10px; color: var(--muted); }
.security-list b { color: var(--accent); }
@media (max-width: 820px) {
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .two-col, .login-layout { grid-template-columns: 1fr; gap: 25px; }
  .login-layout { padding: 30px 0 55px; min-height: auto; }
  .login-layout .hero { margin-bottom: 0; }
}
@media (max-width: 520px) {
  .shell { width: min(1180px, calc(100% - 24px)); }
  .topbar-inner { min-height: 66px; align-items: flex-start; flex-wrap: wrap; padding: 12px 0; }
  .brand { min-width: 0; }
  .userbar { gap: 8px; }
  .userbar span { display: none; }
  .main { padding-top: 30px; }
  .stats { grid-template-columns: 1fr 1fr; gap: 10px; }
  .card { padding: 16px; }
  .stat-value { font-size: 1.5rem; }
}
"""


def _document(title, content):
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body>{content}</body></html>"
    )


# Kept as a named template for callers that used the original console module.
PAGE = _document(
    config.LAB_NAME,
    """<main class="shell main"><div class="login-layout"><section class="hero">
    <div class="eyebrow">Local security operations</div>
    <h1>Android Reset Lab</h1>
    <p>Simulation-only reset orchestration with clear separation of duties,
    tamper-evident audit trails, and an operator view built for confident decisions.</p>
    <div class="notice warning"><strong>Simulation only.</strong> No real devices are touched.</div>
    </section><section class="login-card"><div class="card">
    <div class="eyebrow">Secure access</div><h2>Security Console</h2>
    <p class="muted small">Use a seeded simulation account. Sessions expire automatically.</p>
    <div class="notice error" style="display:{msg_display}">{msg}</div>
    <form method="post" action="/login" autocomplete="off">
      <label for="user">Username</label><input id="user" name="user" maxlength="64" required autofocus>
      <label for="pass">Password</label>
      <div class="password-control">
        <input id="show-password" type="checkbox"><label class="password-toggle" for="show-password">Show password</label>
        <input id="pass" name="pass" type="password" maxlength="128">
        <input id="pass-visible" name="password" type="text" maxlength="128" autocomplete="off" aria-label="Password">
      </div>
      <button type="submit">Continue to dashboard</button>
    </form></div></section></div></main>
    <footer class="footer"><div class="shell">Loopback console · access is audited · policy decisions remain server-side</div></footer>""",
)


def render_login(message=""):
    """Render the unauthenticated page without exposing backend details."""
    display = "block" if message else "none"
    return PAGE.replace("{msg_display}", display).replace("{msg}", html.escape(str(message)))


def _pill(value, kind=""):
    return f'<span class="pill {kind}">{html.escape(str(value))}</span>'


def _status_kind(value):
    return {
        "active": "good",
        "approved": "good",
        "executed": "good",
        "requested": "warning",
        "lost": "warning",
        "stolen": "danger",
        "wiped": "info",
        "INFO": "info",
        "WARNING": "warning",
        "HIGH": "danger",
    }.get(str(value), "")


def collect_dashboard_data():
    """Read current backend state for presentation; never invent summary values."""
    try:
        events = threat_detection._read_log()
    except Exception:
        events = []
    try:
        findings = threat_detection.scan()
        metrics = threat_detection.metrics(findings)
    except Exception:
        findings = {rule: [] for rule in threat_detection.RULES}
        metrics = {}
    try:
        integrity = security_logger.verify_logs()
    except Exception:
        integrity = (False, "unreadable")
    try:
        devices = device_simulator.load_devices()
    except Exception:
        devices = {}
    try:
        requests = reset_workflow._load_requests()
    except Exception:
        requests = {}
    return {
        "events": events,
        "findings": findings,
        "metrics": metrics,
        "integrity": integrity,
        "devices": devices,
        "requests": requests,
    }


def render_dashboard(session, message=""):
    """Render data from the existing backend for an authorized session."""
    data = collect_dashboard_data()
    events = data["events"]
    findings = data["findings"]
    metrics = data["metrics"]
    devices = data["devices"]
    requests = data["requests"]
    integrity_ok, integrity_info = data["integrity"]
    severity_counts = Counter(event.get("severity", "UNKNOWN") for event in events)
    request_counts = Counter(req.get("status", "unknown") for req in requests.values())
    rules_fired = metrics.get("rules_fired", [])
    detection_rate = metrics.get("detection_rate", "unavailable")

    flash = ""
    if message:
        flash = f'<div class="notice {"error" if "denied" in message.lower() or "failed" in message.lower() else "warning"}">{html.escape(message)}</div>'

    integrity_text = "INTACT" if integrity_ok else f"BROKEN · {integrity_info}"
    integrity_kind = "good" if integrity_ok else "danger"
    cards = f"""
      <div class="card"><div class="stat-label">Events recorded</div><div class="stat-value">{len(events)}</div><div class="stat-detail">From the chained audit log</div></div>
      <div class="card"><div class="stat-label">Detection coverage</div><div class="stat-value">{html.escape(str(detection_rate))}</div><div class="stat-detail">{len(rules_fired)} of {len(threat_detection.RULES)} rules fired</div></div>
      <div class="card"><div class="stat-label">Fleet inventory</div><div class="stat-value">{len(devices)}</div><div class="stat-detail">{sum(request_counts.values())} reset requests tracked</div></div>
      <div class="card"><div class="stat-label">Audit integrity</div><div class="stat-value">{_pill(integrity_text, integrity_kind)}</div><div class="stat-detail">Verified at page load</div></div>
    """

    bars = []
    max_severity = max(severity_counts.values(), default=0)
    for severity in ("INFO", "WARNING", "HIGH"):
        count = severity_counts.get(severity, 0)
        width = int((count / max_severity) * 100) if max_severity else 0
        kind = "danger" if severity == "HIGH" else ("warning" if severity == "WARNING" else "")
        bars.append(
            f'<div class="bar-line"><span>{severity}</span><span class="bar-track">'
            f'<span class="bar-fill {kind}" style="width:{width}%"></span></span><strong>{count}</strong></div>'
        )
    rule_rows = []
    for rule in threat_detection.RULES:
        count = len(findings.get(rule, []))
        label = "ALERT" if count else "CLEAR"
        rule_rows.append(
            f'<div class="rule-item"><span>{html.escape(rule.replace("_", " ").title())}</span>'
            f'{_pill(f"{label} · {count}", "danger" if count else "good")}</div>'
        )

    device_rows = []
    for device_id, device in devices.items():
        status = device.get("status", "unknown")
        device_rows.append(
            f"<tr><td><strong>{html.escape(str(device_id))}</strong></td>"
            f"<td>{html.escape(str(device.get('model', '—')))}</td>"
            f"<td>{html.escape(str(device.get('owner', '—')))}</td>"
            f"<td>{_pill(status, _status_kind(status))}</td></tr>"
        )
    device_table = "".join(device_rows) or '<tr><td colspan="4" class="muted">No fleet data available.</td></tr>'

    request_rows = []
    for request_id, request in reversed(list(requests.items())):
        status = request.get("status", "unknown")
        request_rows.append(
            f"<tr><td><code>{html.escape(str(request_id))}</code></td>"
            f"<td>{html.escape(str(request.get('device_id', '—')))}</td>"
            f"<td>{html.escape(str(request.get('requester', '—')))}</td>"
            f"<td>{html.escape(str(request.get('approver') or '—'))}</td>"
            f"<td>{_pill(status, _status_kind(status))}</td></tr>"
        )
    request_table = "".join(request_rows) or '<tr><td colspan="5" class="muted">No reset requests recorded.</td></tr>'

    audit_section = ""
    can_view_logs, _ = authorization.authorize(
        _session_token_from_session(session), "view_logs"
    )
    if can_view_logs:
        audit_rows = []
        for event in events[-8:][::-1]:
            audit_rows.append(
                f"<tr><td>{html.escape(str(event.get('timestamp', '—')))}</td>"
                f"<td>{html.escape(str(event.get('event_type', '—')))}</td>"
                f"<td>{html.escape(str(event.get('actor', '—')))}</td>"
                f"<td>{_pill(event.get('severity', '—'), _status_kind(event.get('severity', '')))}</td></tr>"
            )
        audit_section = f"""
        <section class="card">
          <div class="section-head"><div><div class="eyebrow">Restricted view</div><h2>Recent audit events</h2></div>
          <span class="muted small">Security analyst permission</span></div>
          <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Event</th><th>Actor</th><th>Severity</th></tr></thead>
          <tbody>{''.join(audit_rows) or '<tr><td colspan="4" class="muted">No audit events.</td></tr>'}</tbody></table></div>
        </section>"""

    reset_section = ""
    can_request, _ = authorization.authorize(
        _session_token_from_session(session), "request_reset"
    )
    if can_request:
        options = "".join(
            f'<option value="{html.escape(str(device_id), quote=True)}">'
            f'{html.escape(str(device_id))} · {html.escape(str(device.get("model", "unknown")))}</option>'
            for device_id, device in devices.items()
        )
        reset_section = f"""
        <section class="card form-card">
          <div class="eyebrow">Controlled action</div><h2>Request a simulated reset</h2>
          <p class="muted small">A second account must approve before execution. The simulation guard remains enforced by the workflow.</p>
          <form method="post" action="/request">
            <label for="device">Device</label>
            <select id="device" name="device" required {"disabled" if not options else ""}>
              <option value="">Select a device</option>{options}
            </select>
            <button type="submit" {"disabled" if not options else ""}>Create reset request</button>
          </form>
        </section>"""
    else:
        reset_section = '<section class="card"><div class="eyebrow">Controlled action</div><h2>Reset requests</h2><p class="muted">Your role does not have permission to create reset requests. Access is denied by default.</p></section>'

    content = f"""
    <header class="topbar"><div class="shell topbar-inner"><div class="brand"><div class="brand-mark">AR</div>
      <div><div class="brand-title">{html.escape(config.LAB_NAME)}</div><div class="brand-subtitle">Security operations console</div></div></div>
      <div class="userbar"><span>Signed in as <strong>{html.escape(str(session.get("username", "—")))}</strong> · {html.escape(str(session.get("role", "—")))}</span>
        <form method="post" action="/logout"><button class="button-secondary" type="submit">Log out</button></form></div>
    </div></header>
    <main class="shell main">{flash}
      <section class="hero"><div class="eyebrow">Simulation control plane</div><h1>Good morning, {html.escape(str(session.get("username", "operator")))}</h1>
      <p>Observe the lab state, review detection signals, and request resets without crossing the four-eyes approval boundary.</p></section>
      <div class="notice warning"><strong>SIMULATION MODE</strong> · This environment performs simulated device-management operations only.</div>
      <section class="grid stats">{cards}</section>
      <section class="grid two-col"><div class="card"><div class="section-head"><div><div class="eyebrow">Detection</div><h2>Signal overview</h2></div><span class="muted small">Current log snapshot</span></div>
        <div class="bars">{''.join(bars)}</div></div>
        <div class="card"><div class="section-head"><div><div class="eyebrow">Policy rules</div><h2>Threat coverage</h2></div></div><div class="rule-list">{''.join(rule_rows)}</div></div>
      </section>
      <div class="section-head"><div><div class="eyebrow">Inventory</div><h2>Simulated device fleet</h2></div><span class="muted small">Live backend data</span></div>
      <section class="card"><div class="table-wrap"><table><thead><tr><th>Device</th><th>Model</th><th>Owner</th><th>Status</th></tr></thead><tbody>{device_table}</tbody></table></div></section>
      <div class="section-head"><div><div class="eyebrow">Workflow</div><h2>Reset requests</h2></div><span class="muted small">No execution is implied by a request</span></div>
      <section class="card"><div class="table-wrap"><table><thead><tr><th>Request ID</th><th>Device</th><th>Requester</th><th>Approver</th><th>Status</th></tr></thead><tbody>{request_table}</tbody></table></div></section>
      <div class="grid two-col" style="margin-top:16px">{reset_section}<div class="card"><div class="eyebrow">Audit</div><h2>Integrity verification</h2><p class="muted">The hash chain is checked when this dashboard is rendered.</p><p>{_pill(integrity_text, integrity_kind)}</p></div></div>
      {audit_section}
    </main><footer class="footer"><div class="shell">Simulation only · server-side RBAC · four-eyes approval · tamper-evident audit</div></footer>"""
    return _document(config.LAB_NAME + " · Dashboard", content)


# Simple in-memory sliding-window rate limit, retained for compatibility.
rate_limit_store = defaultdict(deque)


def is_rate_limited(ip):
    """Return True when an IP has reached the configured POST request limit."""
    now = time.time()
    window_start = now - config.RATE_LIMIT_WINDOW_SECONDS
    dq = rate_limit_store[ip]
    while dq and dq[0] < window_start:
        dq.popleft()
    if len(dq) >= config.RATE_LIMIT_REQUESTS:
        return True
    dq.append(now)
    return False


def _session_token_from_session(session):
    """Return a session token only for internal permission checks in rendering."""
    return session.get("_token", "") if isinstance(session, dict) else ""


class Handler(BaseHTTPRequestHandler):
    def _send_html(self, body, status=200, extra_headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'none'; img-src 'none'; style-src 'unsafe-inline'; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _page(self, msg="", status=200):
        """Compatibility helper for unauthenticated/error responses."""
        self._send_html(render_login(msg), status)

    def _cookie_token(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookies.get(SESSION_COOKIE) or cookies.get("android_reset_session")
        return morsel.value if morsel else None

    def _current_session(self):
        token = self._cookie_token()
        if not token:
            return None, None
        session = authentication.check_session(token)
        if session is None:
            return None, token
        # Keep the token private to this request for permission checks.
        current = dict(session)
        current["_token"] = token
        return current, token

    def _respond_dashboard(self, session, token, message="", status=200):
        self._send_html(render_dashboard(session, message), status)

    def _session_cookie(self, token, max_age=None):
        cookie = SimpleCookie()
        cookie[SESSION_COOKIE] = token
        cookie[SESSION_COOKIE]["path"] = "/"
        cookie[SESSION_COOKIE]["httponly"] = True
        cookie[SESSION_COOKIE]["samesite"] = "Strict"
        if max_age is not None:
            cookie[SESSION_COOKIE]["max-age"] = str(max_age)
        return cookie.output(header="").strip()

    def _parse_form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return None, "Invalid request"
        if length < 0:
            return None, "Invalid request"
        if length > MAX_REQUEST_BYTES:
            return None, "Request too large"
        try:
            raw = self.rfile.read(length).decode("utf-8")
            return parse_qs(raw, keep_blank_values=True, max_num_fields=10), None
        except (UnicodeDecodeError, ValueError):
            return None, "Invalid request"

    @staticmethod
    def _value(form, name, limit, strip=True):
        values = form.get(name, [])
        if len(values) != 1 or len(values[0]) > limit:
            return None
        value = values[0]
        return value.strip() if strip else value

    def _authorize(self, token, action):
        session = authentication.check_session(token) if token else None
        if session is None:
            return None, "no session"
        ok, reason = authorization.authorize(token, action)
        if not ok:
            security_logger.log_event(
                "ACCESS_DENIED",
                session.get("username", "-"),
                f"web console: {action} denied",
                severity="WARNING",
                role=session.get("role", "-"),
            )
            return session, reason
        return session, None

    def log_message(self, format, *args):
        return

    def do_GET(self):
        path = urlsplit(self.path).path
        if path not in ("/", "/dashboard", "/login"):
            self._page("Page not found", status=404)
            return
        session, token = self._current_session()
        if path == "/login" and session is None:
            self._send_html(render_login())
            return
        if session is None:
            self._send_html(render_login("Please sign in to continue."), status=401)
            return
        session["_token"] = token
        ok, reason = authorization.authorize(token, "view_dashboard")
        if not ok:
            self._send_html(render_login("Access denied."), status=403)
            return
        self._respond_dashboard(session, token)

    def do_POST(self):
        client_ip = self.client_address[0]
        if is_rate_limited(client_ip):
            security_logger.log_event(
                "RATE_LIMITED", client_ip, "web console rate limit exceeded", severity="WARNING"
            )
            self._page("Too many requests. Please wait a minute and try again.", status=429)
            return

        form, error = self._parse_form()
        if error:
            self._page(error, status=413 if error == "Request too large" else 400)
            return
        path = urlsplit(self.path).path

        if path == "/login":
            user = self._value(form, "user", 64)
            if user is None:
                user = self._value(form, "username", 64)
            password = self._value(form, "pass", 128, strip=False)
            if not password:
                password = self._value(form, "password", 128, strip=False)
            if user is None or password is None or not user or not password:
                self._page("Missing or invalid credentials", status=400)
                return
            ok, message = authentication.login(user, password)
            if not ok:
                security_logger.log_event(
                    "LOGIN_FAILED", user, f"web console: {message}", severity="WARNING"
                )
                self._page("Login failed: " + message, status=401)
                return
            token = authentication.start_session(user)
            session = authentication.check_session(token)
            security_logger.log_event(
                "LOGIN_SUCCESS",
                user,
                "web console login",
                role=session.get("role", "-") if session else "-",
            )
            if session is None:
                self._page("Unable to create session", status=500)
                return
            session["_token"] = token
            self._send_html(
                render_dashboard(session),
                extra_headers=[("Set-Cookie", self._session_cookie(token, config.SESSION_TTL_MINUTES * 60))],
            )
            return

        session, token = self._current_session()
        if path == "/logout":
            if session is not None and token:
                security_logger.log_event(
                    "LOGOUT",
                    session.get("username", "-"),
                    "web console logout",
                    role=session.get("role", "-"),
                )
                authentication.end_session(token)
            self._send_html(
                render_login("You have been signed out."),
                extra_headers=[("Set-Cookie", self._session_cookie("", 0))],
            )
            return

        if path == "/request":
            if session is None or token is None:
                self._send_html(render_login("Please sign in to request a reset."), status=401)
                return
            if not config.SIMULATION_MODE:
                self._respond_dashboard(
                    session, token, "Simulation guard: console actions are disabled.", status=503
                )
                return
            authorized_session, reason = self._authorize(token, "request_reset")
            if reason:
                self._respond_dashboard(session, token, "Request denied: " + reason, status=403)
                return
            device = self._value(form, "device", 20)
            if device is None or not device or any(ord(char) < 32 for char in device):
                self._respond_dashboard(session, token, "Missing or invalid device.", status=400)
                return
            ok, info = reset_workflow.request_reset(token, device)
            if ok:
                message = "Request created: " + info + ". A second account must approve it."
                self._respond_dashboard(session, token, message)
            else:
                self._respond_dashboard(session, token, "Request denied: " + info, status=403)
            return

        self._page("Page not found", status=404)


if __name__ == "__main__":
    device_simulator.seed_devices()
    server = HTTPServer(("127.0.0.1", 8000), Handler)
    print("console on http://127.0.0.1:8000 - Ctrl+C stops it")
    server.serve_forever()
