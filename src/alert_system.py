"""
Alert System for security violations
"""

"""Alert system: log and print security alerts.

This simplified alert system intentionally avoids external dependencies
and focuses on local logging + console notification. Email support is
left out to keep the dependency surface minimal and avoid credential
management in this repository.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable
from config import Config


class AlertSystem:
    """Lightweight alerting: log alerts to file and print to console."""

    def __init__(self):
        self.config = Config()
        alerts_log = self.config.get_alerts_log_path()
        self.alerts_log = Path(alerts_log)
        self.alerts_log.parent.mkdir(parents=True, exist_ok=True)

    def send_alert(self, event_type: str, src_path: str, dest_path: str = None, violations: Iterable[str] = None, severity: str = 'MEDIUM') -> None:
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'source_path': src_path,
            'destination_path': dest_path,
            'violations': list(violations or []),
            'severity': severity,
        }
        try:
            with open(self.alerts_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_data, default=str) + "\n")
        except Exception:
            pass
        # Console summary
        self.print_alert(alert_data)

    def print_alert(self, alert_data: dict) -> None:
        sev = alert_data.get('severity', 'MEDIUM')
        print(f"[ALERT - {sev}] {alert_data.get('event_type')} {alert_data.get('source_path')}")

    def get_recent_alerts(self, limit: int = 10):
        alerts = []
        try:
            with open(self.alerts_log, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-limit:]
            for line in lines:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    continue
        except Exception:
            pass
        return alerts