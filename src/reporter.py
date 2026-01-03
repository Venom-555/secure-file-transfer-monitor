"""Reporter utilities for startup and runtime event reporting.

Creates:
- baseline.json (written by IntegrityChecker)
- reports/startup_report.txt
- reports/runtime_events.log (JSON lines)

These helpers only write files; they do not execute or modify runtime behavior.
"""
import json
from pathlib import Path
from datetime import datetime


def ensure_reports_dir(reports_dir=None):
    """Ensure the reports directory exists and return its Path.

    The directory may be provided explicitly via `reports_dir`, or by the
    environment variable `REPORTS_DIR`. Falls back to `reports/`.
    """
    if not reports_dir:
        import os
        reports_dir = os.environ.get('REPORTS_DIR')
    d = Path(reports_dir) if reports_dir else Path('reports')
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_startup_report(summary, baseline, output_path=None, reports_dir=None):
    """Write a human-readable startup report summarizing baseline scan."""
    d = ensure_reports_dir(reports_dir)
    p = Path(output_path) if output_path else d / 'startup_report.txt'
    try:
        with open(p, 'w', encoding='utf-8') as f:
            f.write(f"Startup Baseline Report\nGenerated: {datetime.now().isoformat()}\n")
            f.write(f"Total files scanned: {summary.get('total_files')}\n")
            f.write(f"Hashes recorded: {summary.get('hashes_recorded')}\n")
            # Ensure the initial integrity status is explicit
            f.write(f"Initial integrity status: {summary.get('status') or 'BASELINE_CREATED'}\n")
            f.write('\nSample entries (up to 20):\n')
            count = 0
            # baseline is a dict mapping canonical path -> metadata
            for path, meta in list(baseline.items())[:20]:
                try:
                    f.write(f"- {path} | size={meta.get('size')} | hash={meta.get('hash')}\n")
                except Exception:
                    f.write(f"- {path} | metadata unavailable\n")
                count += 1
        return True
    except Exception:
        return False


def log_runtime_event(event, output_path=None, reports_dir=None):
    """Append a runtime event as a JSON line to `reports/runtime_events.log`."""
    d = ensure_reports_dir(reports_dir)
    p = Path(output_path) if output_path else d / 'runtime_events.log'
    try:
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event, default=str) + "\n")
        return True
    except Exception:
        return False
