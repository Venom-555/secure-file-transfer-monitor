#!/usr/bin/env python3
"""
Secure File Transfer Monitoring System - Main Monitor
"""

import os
import time
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import Config
from logger import Logger
from alert_system import AlertSystem
from integrity_checker import IntegrityChecker
from reporter import write_startup_report, log_runtime_event


class FileTransferHandler(FileSystemEventHandler):
    """Handle filesystem events and perform integrity checks + reporting.

    reports_dir: optional path where reports are written. If None, the
    reporter will use its default `reports/` directory or the
    REPORTS_DIR environment variable.
    """

    def __init__(self, reports_dir=None):
        self.config = Config()
        self.logger = Logger(self.config.config["logging"]["transfer_log"])
        self.alert = AlertSystem()
        self.integrity = IntegrityChecker()
        # reporter functions write files under `reports/` by default
        self.reports_dir = reports_dir
        self.sensitive_dirs = self.config.get_sensitive_directories()
        self.restricted_extensions = self.config.get_restricted_extensions()

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("CREATED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event("MOVED", event.src_path, event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event("DELETED", event.src_path)

    def process_event(self, event_type, src_path, dest_path=None):
        timestamp = datetime.now().isoformat()
        user = os.getenv("USERNAME") or os.getenv("USER") or "UNKNOWN"

        is_sensitive = self.is_sensitive_file(src_path)
        integrity = {"status": "NOT_CHECKED"}

        # Resolve canonical path for baseline lookups
        try:
            file_key = str(Path(src_path).resolve())
        except Exception:
            file_key = str(Path(src_path))

        # Handle different event types with baseline comparisons and updates
        try:
            if event_type == "MODIFIED":
                new_hash = self.integrity.calculate_hash(src_path)
                old_hash = self.integrity.baseline.get(file_key, {}).get('hash') if self.integrity.baseline else None
                if old_hash is None:
                    # Unknown file, register it
                    self.integrity.baseline[file_key] = {
                        'hash': new_hash,
                        'size': Path(src_path).stat().st_size if Path(src_path).exists() else 0,
                        'first_seen': datetime.now().isoformat()
                    }
                    self.integrity.save_baseline()
                    integrity = {"status": "NEW_FILE_REGISTERED", "current_hash": new_hash, "stored_hash": None, "match": True}
                else:
                    integrity = {"current_hash": new_hash, "stored_hash": old_hash}
                    integrity["match"] = (new_hash == old_hash)
                    integrity["status"] = "MATCH" if integrity["match"] else "INTEGRITY_FAILED"
                    if not integrity["match"]:
                        print(f"⚠️  Integrity mismatch detected for: {src_path}")

            elif event_type == "CREATED":
                # New file created - add to baseline
                new_hash = self.integrity.calculate_hash(src_path)
                self.integrity.baseline[file_key] = {
                    'hash': new_hash,
                    'size': Path(src_path).stat().st_size if Path(src_path).exists() else 0,
                    'first_seen': datetime.now().isoformat()
                }
                self.integrity.save_baseline()
                integrity = {"status": "NEW_FILE_REGISTERED", "current_hash": new_hash, "stored_hash": None, "match": True}

            elif event_type == "DELETED":
                # Mark removal in baseline if present
                old_hash = self.integrity.baseline.get(file_key, {}).get('hash') if self.integrity.baseline else None
                if file_key in self.integrity.baseline:
                    self.integrity.baseline.pop(file_key, None)
                    self.integrity.save_baseline()
                integrity = {"status": "FILE_REMOVED", "stored_hash": old_hash, "current_hash": None, "match": False}

            elif event_type == "MOVED":
                # A rename/move: update baseline keys
                try:
                    dest_key = str(Path(dest_path).resolve()) if dest_path else None
                except Exception:
                    dest_key = str(dest_path) if dest_path else None
                old_hash = self.integrity.baseline.get(file_key, {}).get('hash') if self.integrity.baseline else None
                if file_key in self.integrity.baseline and dest_key:
                    self.integrity.baseline[dest_key] = self.integrity.baseline.pop(file_key)
                    self.integrity.save_baseline()
                integrity = {"status": "MOVED", "stored_hash": old_hash, "current_hash": old_hash, "match": True}

            else:
                # Fallback checks (non-sensitive quick check)
                integrity = self.integrity.check_file(src_path)
        except Exception:
            integrity = {"status": "ERROR", "current_hash": None, "stored_hash": None, "match": False}

        violations = self.check_policy_violations(src_path, dest_path)
        unauthorized = bool(violations)

        if unauthorized:
            self.alert.send_alert(event_type, src_path, dest_path, violations)

        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "source_path": src_path,
            "destination_path": dest_path,
            "user": user,
            "process": "UNKNOWN",
            "sensitive": is_sensitive,
            "unauthorized": unauthorized,
            "integrity_check": integrity.get("status"),
            "violations": violations,
        }

        self.logger.log_transfer(log_entry)
        self.print_summary(log_entry)

        # Compose runtime report entry and write to runtime_events.log
        try:
            old_hash = integrity.get('stored_hash')
            new_hash = integrity.get('current_hash')
            # Risk level heuristics
            risk = 'LOW'
            if integrity.get('status') in ('INTEGRITY_FAILED', 'MISMATCH'):
                risk = 'HIGH'
            elif is_sensitive:
                risk = 'MEDIUM'

            event_report = {
                'timestamp': timestamp,
                'event_type': event_type,
                'file_path': src_path,
                'old_hash': old_hash,
                'new_hash': new_hash,
                'risk_level': risk,
                'status': integrity.get('status'),
                'violations': violations
            }
            # Persist runtime event to runtime_events.log under reports dir
            try:
                log_runtime_event(event_report, reports_dir=self.reports_dir)
            except Exception:
                # Ensure event processing doesn't crash on logging failures
                pass
        except Exception:
            pass

    def is_sensitive_file(self, path):
        path = str(path)
        if any(path.startswith(d) for d in self.sensitive_dirs):
            return True
        return Path(path).suffix.lower() in self.restricted_extensions

    def check_policy_violations(self, src, dest):
        violations = []
        if dest and (dest.startswith("\\") or ":" in dest):
            violations.append("EXTERNAL_TRANSFER")
        if Path(src).suffix.lower() in self.restricted_extensions:
            violations.append("RESTRICTED_FILE_TYPE")
        return violations

    def print_summary(self, log):
        status = "ALERT" if log["unauthorized"] else "OK"
        print(f"[{status}] {log['event_type']} -> {log['source_path']}")


class FileTransferMonitor:

    def __init__(self, baseline_path=None, reports_dir=None):
        self.config = Config()
        self.observer = Observer()
        self.baseline_path = baseline_path
        self.reports_dir = reports_dir
        # create handler with reports_dir so it can write runtime events
        self.handler = FileTransferHandler(reports_dir=self.reports_dir)
        # If a baseline path was provided, ensure the integrity checker uses it
        try:
            if self.baseline_path:
                from pathlib import Path as _P
                self.handler.integrity.baseline_path = _P(self.baseline_path)
                # reload baseline from the provided path if present
                self.handler.integrity.baseline = self.handler.integrity.load_baseline(self.baseline_path)
        except Exception:
            pass

    def start(self):
        print("Starting Secure File Transfer Monitor")
        watch_paths = self.config.get_watch_paths()

        # --- Startup baseline scan ---
        try:
            # Perform a full startup baseline scan and persist baseline.json
            summary, baseline = self.handler.integrity.generate_baseline(watch_paths, baseline_path=self.baseline_path)
            # write startup report into reports directory (if provided)
            try:
                write_startup_report(summary, baseline, reports_dir=self.reports_dir)
            except Exception:
                pass
            print(f"Baseline scan complete: {summary.get('total_files')} files")
        except Exception:
            print("Warning: baseline scan failed or found no files")

        for path in watch_paths:
            if Path(path).exists():
                self.observer.schedule(self.handler, path, recursive=True)
                print(f"Monitoring {path}")
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()


def main(baseline_path=None, reports_dir=None):
    # Allow callers to request alternate baseline and reports locations
    import os
    if reports_dir:
        os.environ['REPORTS_DIR'] = str(reports_dir)

    monitor = FileTransferMonitor(baseline_path=baseline_path, reports_dir=reports_dir)
    monitor.start()


if __name__ == "__main__":
    main()
