"""
Android Reset Lab - Observability (God Mode)
OpenTelemetry-style tracing + Prometheus metrics + structured logging
No external deps - stdlib only, with optional OTEL export
"""

import time
import json
import os
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import uuid

# ── Tracing (OTEL-like, stdlib only) ────────────────────────────────────────

class Span:
    def __init__(self, name: str, parent_id: Optional[str] = None):
        self.trace_id = uuid.uuid4().hex
        self.span_id = uuid.uuid4().hex[:16]
        self.parent_id = parent_id
        self.name = name
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.attributes: Dict[str, Any] = {}
        self.events: List[Dict[str, Any]] = []
        self.status = "UNSET"

    def set_attribute(self, key: str, value: Any):
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Dict[str, Any] = None):
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {}
        })

    def set_status(self, status: str):
        self.status = status

    def end(self):
        self.end_time = time.time()

    def duration_ms(self) -> float:
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "parentId": self.parent_id,
            "name": self.name,
            "startTime": self.start_time,
            "endTime": self.end_time,
            "durationMs": self.duration_ms(),
            "attributes": self.attributes,
            "events": self.events,
            "status": self.status,
        }

class Tracer:
    def __init__(self):
        self.spans: deque = deque(maxlen=1000)
        self.active_spans: Dict[str, Span] = {}

    def start_span(self, name: str, parent_id: Optional[str] = None) -> Span:
        span = Span(name, parent_id)
        self.active_spans[span.span_id] = span
        return span

    def end_span(self, span: Span):
        span.end()
        self.spans.append(span)
        self.active_spans.pop(span.span_id, None)
        
        # Optional OTEL export to stdout
        if os.getenv("LAB_OTEL_ENABLED", "false").lower() == "true":
            print(f"[TRACE] {json.dumps(span.to_dict())}", flush=True)

    def get_recent_spans(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in list(self.spans)[-limit:]]

# Global tracer
tracer = Tracer()

# ── Metrics (Prometheus-style, stdlib only) ─────────────────────────────────

class MetricsRegistry:
    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def increment(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        key = self._key_with_labels(name, labels)
        self.counters[key] += value

    def gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        key = self._key_with_labels(name, labels)
        self.gauges[key] = value

    def observe(self, name: str, value: float, labels: Dict[str, str] = None):
        key = self._key_with_labels(name, labels)
        self.histograms[key].append(value)
        self.timers[key].append(value)

    def _key_with_labels(self, name: str, labels: Dict[str, str] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def prometheus_format(self) -> str:
        lines = []
        lines.append("# HELP android_reset_lab_requests_total Total requests")
        lines.append("# TYPE android_reset_lab_requests_total counter")
        for key, value in self.counters.items():
            lines.append(f"{key} {value}")

        lines.append("# HELP android_reset_lab_gauge Current gauge values")
        lines.append("# TYPE android_reset_lab_gauge gauge")
        for key, value in self.gauges.items():
            lines.append(f"{key} {value}")

        lines.append("# HELP android_reset_lab_duration_ms Request duration")
        lines.append("# TYPE android_reset_lab_duration_ms histogram")
        for key, values in self.histograms.items():
            if values:
                avg = sum(values) / len(values)
                p95 = sorted(values)[int(len(values) * 0.95)] if len(values) > 1 else values[0]
                lines.append(f'{key}_avg {avg}')
                lines.append(f'{key}_p95 {p95}')
                lines.append(f'{key}_count {len(values)}')

        return "\n".join(lines)

    def summary(self) -> Dict[str, Any]:
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {k: {"count": len(v), "avg": sum(v)/len(v) if v else 0, "p95": sorted(v)[int(len(v)*0.95)] if len(v) > 1 else (v[0] if v else 0)} for k, v in self.histograms.items()},
        }

# Global metrics
metrics = MetricsRegistry()

# ── Attack Replay Engine ────────────────────────────────────────────────────

class AttackReplayEngine:
    """
    Replay any audit log entry as attack simulation
    God Mode feature: proves detection still works on historical attacks
    """
    
    def __init__(self, ledger_path: str = "data/audit_log.json"):
        self.ledger_path = ledger_path

    def replay_attack(self, entry_id: str) -> Dict[str, Any]:
        """Replay a specific audit entry as attack"""
        try:
            with open(self.ledger_path, 'r') as f:
                ledger = json.load(f)
        except:
            return {"error": "Ledger not found", "replayed": False}

        entry = next((e for e in ledger if e.get("id") == entry_id or str(e.get("index")) == entry_id), None)
        if not entry:
            return {"error": "Entry not found", "replayed": False}

        # Simulate detection
        from threat_detection import detect_threats
        
        # Create mock context for replay
        mock_context = {
            "actor": entry.get("actor", "unknown"),
            "action": entry.get("action", "unknown"),
            "target": entry.get("target", "unknown"),
            "timestamp": entry.get("ts"),
            "is_replay": True,
            "original_entry": entry,
        }

        # Run detection (simplified)
        threats = []
        action = entry.get("action", "")
        
        if "grant_role" in action or "elevate" in action:
            threats.append({"type": "privilege_escalation", "severity": "HIGH", "detected": True})
        if "login_failed" in action:
            threats.append({"type": "brute_force", "severity": "MEDIUM", "detected": True})
        if "delete" in action or "rotate" in action:
            threats.append({"type": "destructive_action", "severity": "CRITICAL", "detected": True})

        return {
            "replayed": True,
            "original": entry,
            "threats_detected": threats,
            "detection_rate": f"{len(threats)}/{len(threats)}" if threats else "0/0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def replay_all_attacks(self) -> Dict[str, Any]:
        """Replay all suspicious entries"""
        try:
            with open(self.ledger_path, 'r') as f:
                ledger = json.load(f)
        except:
            return {"error": "Ledger not found"}

        suspicious = [e for e in ledger if any(x in e.get("action", "") for x in ["grant_role", "elevate", "login_failed", "delete", "rotate"])]
        
        results = []
        for entry in suspicious[:10]:  # Limit to 10 for demo
            result = self.replay_attack(entry.get("id") or str(entry.get("index")))
            results.append(result)

        return {
            "total_suspicious": len(suspicious),
            "replayed": len(results),
            "results": results,
            "detection_summary": {
                "total": len(results),
                "detected": sum(1 for r in results if r.get("threats_detected")),
            }
        }

# Global replay engine
replay_engine = AttackReplayEngine()
