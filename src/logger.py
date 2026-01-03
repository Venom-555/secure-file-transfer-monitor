"""
Logging module for file transfer events
"""

import json
from datetime import datetime
from pathlib import Path
import logging


class Logger:
    """Handles logging of file transfer events.

    Logs are written as JSON Lines. A CSV companion file is also maintained
    for simple spreadsheet analysis.
    """

    def __init__(self, log_file="logs/file_transfer.log", max_size_mb=10):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(max_size_mb * 1024 * 1024)
        self.logger = logging.getLogger('secure_monitor.logger')

        if not self.log_file.exists():
            self._init_log_file()

    def _init_log_file(self):
        header = {
            "system": "Secure File Transfer Monitor",
            "start_time": datetime.now().isoformat(),
            "log_format": "JSON Lines"
        }
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(header) + "\n")

    def _rotate_if_needed(self):
        try:
            if self.log_file.exists() and self.log_file.stat().st_size > self.max_bytes:
                archive = self.log_file.with_suffix(self.log_file.suffix + ".old")
                if archive.exists():
                    archive.unlink()
                self.log_file.rename(archive)
                self._init_log_file()
        except Exception:
            pass

    def log_transfer(self, log_entry):
        """Append a transfer log entry (dict) as a JSON line."""
        try:
            self._rotate_if_needed()
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry, default=str) + "\n")
            self._log_to_csv(log_entry)
        except Exception:
            pass

    def _log_to_csv(self, log_entry):
        csv_file = self.log_file.with_suffix('.csv')

        # Standardized per-event CSV used by report pipeline
        summary_dir = Path(__file__).parents[1] / 'reports'
        summary_dir.mkdir(parents=True, exist_ok=True)
        summary_csv = summary_dir / 'security_summary.csv'

        # Standardized column names required by the pipeline
        csv_fields = [
            'timestamp', 'event_type', 'source_path', 'destination_path',
            'user', 'process', 'severity', 'is_sensitive', 'is_unauthorized',
            'integrity_check', 'violations'
        ]

        # Determine boolean flags and severity
        sensitive_flag = bool(log_entry.get('sensitive', False))
        unauthorized_flag = bool(log_entry.get('unauthorized', False))
        violations = log_entry.get('violations') or []
        severity = 'LOW'
        if unauthorized_flag or any(v in ('EXTERNAL_TRANSFER', 'RESTRICTED_FILE_TYPE') for v in violations):
            severity = 'HIGH'
        elif sensitive_flag:
            severity = 'MEDIUM'

        csv_data = {
            'timestamp': log_entry.get('timestamp', ''),
            'event_type': log_entry.get('event_type', ''),
            'source_path': log_entry.get('source_path', ''),
            'destination_path': log_entry.get('destination_path', ''),
            'user': log_entry.get('user', ''),
            'process': log_entry.get('process', ''),
            'severity': severity,
            'is_sensitive': '1' if sensitive_flag else '0',
            'is_unauthorized': '1' if unauthorized_flag else '0',
            'integrity_check': log_entry.get('integrity_check', ''),
            'violations': ';'.join(violations)
        }

        import csv
        try:
            # write companion CSV next to JSON log for compatibility
            if not csv_file.exists():
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=list(csv_data.keys()))
                    writer.writeheader()
                    writer.writerow(csv_data)
            else:
                with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=list(csv_data.keys()))
                    writer.writerow(csv_data)

            # also append to the reports/security_summary.csv (real-time summary feed)
            write_header = not summary_csv.exists()
            with open(summary_csv, 'a', newline='', encoding='utf-8') as sf:
                writer = csv.DictWriter(sf, fieldnames=csv_fields)
                if write_header:
                    writer.writeheader()
                # ensure we only write fields expected by the summary CSV
                row = {k: csv_data.get(k, '') for k in csv_fields}
                writer.writerow(row)

            self.logger.debug(f"Wrote CSV rows: companion={csv_file}, summary={summary_csv}")
        except Exception as e:
            # don't fail the monitor on logging errors, but emit debug for troubleshooting
            try:
                self.logger.debug(f"Failed to write CSV logs: {e}")
            except Exception:
                pass
        # update a lightweight summary.json for the dashboard to consume
        try:
            import csv as _csv
            summary_json = summary_dir / 'summary.json'
            total = 0
            unauth = 0
            sens = 0
            with open(summary_csv, 'r', encoding='utf-8') as sf:
                reader = _csv.DictReader(sf)
                for r in reader:
                    total += 1
                    if str(r.get('is_unauthorized','')).strip().lower() in ('1','true','yes'):
                        unauth += 1
                    if str(r.get('is_sensitive','')).strip().lower() in ('1','true','yes'):
                        sens += 1

            summary_data = {
                'generated': datetime.now().isoformat(),
                'statistics': {
                    'total_events': total,
                    'unauthorized_events': unauth,
                    'sensitive_events': sens,
                    'unauthorized_percentage': (unauth / total * 100) if total > 0 else 0
                }
            }
            try:
                with open(summary_json, 'w', encoding='utf-8') as sj:
                    json.dump(summary_data, sj, indent=2)
                self.logger.debug(f"Updated summary.json: {summary_json}")
            except Exception:
                pass
        except Exception:
            pass

    def get_recent_logs(self, limit=50):
        logs = []
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                start_idx = 1 if lines and lines[0].strip().startswith('{"system"') else 0
                for line in lines[start_idx:][-limit:]:
                    try:
                        logs.append(json.loads(line.strip()))
                    except Exception:
                        continue
        except Exception:
            pass
        return logs

    def generate_summary_report(self):
        logs = self.get_recent_logs(limit=1000)
        if not logs:
            return {"error": "No logs found"}

        total_events = len(logs)
        unauthorized_events = sum(1 for log in logs if log.get('unauthorized'))
        sensitive_events = sum(1 for log in logs if log.get('sensitive'))

        event_types = {}
        users = {}
        violations = {}

        for log in logs:
            event_type = log.get('event_type', 'UNKNOWN')
            event_types[event_type] = event_types.get(event_type, 0) + 1

            user = log.get('user', 'UNKNOWN')
            users[user] = users.get(user, 0) + 1

            for violation in log.get('violations', []):
                violations[violation] = violations.get(violation, 0) + 1

        report = {
            "report_time": datetime.now().isoformat(),
            "period": {
                "start": logs[0].get('timestamp'),
                "end": logs[-1].get('timestamp')
            },
            "statistics": {
                "total_events": total_events,
                "unauthorized_events": unauthorized_events,
                "sensitive_events": sensitive_events,
                "unauthorized_percentage": (unauthorized_events / total_events * 100) if total_events > 0 else 0
            },
            "event_breakdown": event_types,
            "user_activity": users,
            "violation_summary": violations,
            "recent_alerts": [log for log in logs[-10:] if log.get('unauthorized')]
        }

        return report