# reports.py - dashboard and report generation
import json
from collections import Counter

import config
import security_logger
import threat_detection


def dashboard():
    events = threat_detection._read_log()
    by_severity = Counter(e["severity"] for e in events)
    findings = threat_detection.scan()
    m = threat_detection.metrics(findings)

    lines = []
    lines.append("=" * 46)
    lines.append("  " + config.LAB_NAME + " - SECURITY DASHBOARD")
    lines.append("=" * 46)
    lines.append("  events total: " + str(len(events)))
    for sev in ["INFO", "WARNING", "HIGH"]:
        bar = "#" * by_severity.get(sev, 0)
        lines.append("  " + sev.ljust(9) + str(by_severity.get(sev, 0)).rjust(3) + "  " + bar)
    lines.append("-" * 46)
    for rule in threat_detection.RULES:
        state = "ALERT" if findings[rule] else "ok"
        lines.append("  " + rule.ljust(22) + state)
    lines.append("-" * 46)
    lines.append("  detection rate: " + m["detection_rate"])
    ok, info = security_logger.verify_logs()
    lines.append("  log integrity:  " + ("INTACT" if ok else "BROKEN line " + str(info)))
    lines.append("=" * 46)
    return "\n".join(lines)


def write_report():
    text = dashboard()
    with open("reports/dashboard.txt", "w") as f:
        f.write(text + "\n")
    return text


if __name__ == "__main__":
    print(dashboard())
    write_report()
    print("(saved to reports/dashboard.txt)")