"""Reporter utilities for startup and runtime event reporting.

This module provides small, dependency-free helpers that produce both
CSV and JSON reports in the `reports/` directory. Each runtime event
record will include the canonical fields required by the project.
"""
import json
import csv
import os
from pathlib import Path
from datetime import datetime
from typing import Iterable, Mapping, List


def ensure_reports_dir(reports_dir: str = None) -> Path:
    """Return Path to reports directory, creating it if necessary."""
    if not reports_dir:
        reports_dir = os.environ.get('REPORTS_DIR')
    d = Path(reports_dir) if reports_dir else Path('reports')
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_startup_report(summary: Mapping, baseline: Mapping, output_path: str = None, reports_dir: str = None) -> bool:
    """Write a concise startup report and return True on success."""
    d = ensure_reports_dir(reports_dir)
    p = Path(output_path) if output_path else d / 'startup_report.txt'
    try:
        with open(p, 'w', encoding='utf-8') as f:
            f.write(f"Startup Baseline Report\nGenerated: {datetime.now().isoformat()}\n")
            f.write(f"Total files scanned: {summary.get('total_files')}\n")
            f.write(f"Hashes recorded: {summary.get('hashes_recorded')}\n")
            f.write(f"Initial integrity status: {summary.get('status') or 'BASELINE_CREATED'}\n\n")
            f.write('Sample entries (up to 20):\n')
            for i, (path, meta) in enumerate(list(baseline.items())[:20]):
                try:
                    f.write(f"- {path} | size={meta.get('size')} | hash={meta.get('hash')}\n")
                except Exception:
                    f.write(f"- {path} | metadata unavailable\n")
        return True
    except Exception:
        return False


def write_report_records(records: Iterable[Mapping], reports_dir: str = None, prefix: str = None) -> bool:
    """Write `records` to a JSON and CSV file in `reports_dir`.

    Each record must contain: timestamp, file_path, event_type, old_hash,
    new_hash, severity. Additional fields are allowed.
    """
    d = ensure_reports_dir(reports_dir)
    ts = datetime.now().strftime('%Y%m%dT%H%M%S')
    base = f"runtime_report_{ts}" if not prefix else f"{prefix}_{ts}"
    json_path = d / f"{base}.json"
    csv_path = d / f"{base}.csv"

    recs: List[Mapping] = list(records)
    # write JSON
    try:
        with open(json_path, 'w', encoding='utf-8') as jf:
            json.dump(recs, jf, default=str, indent=2)
    except Exception:
        return False

    # write CSV with deterministic columns
    fieldnames = ['timestamp', 'file_path', 'event_type', 'old_hash', 'new_hash', 'severity']
    # include any extra fields found across records while keeping core fields first
    extra_fields = []
    for r in recs:
        for k in r.keys():
            if k not in fieldnames and k not in extra_fields:
                extra_fields.append(k)
    all_fields = fieldnames + extra_fields

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.DictWriter(cf, fieldnames=all_fields)
            writer.writeheader()
            for r in recs:
                row = {k: (r.get(k) if k in r else '') for k in all_fields}
                writer.writerow(row)
    except Exception:
        return False

    return True


def log_runtime_event(event: Mapping, reports_dir: str = None) -> bool:
    """Append a single event to the rolling runtime_events.log and companion CSV.

    This helper is intentionally lightweight and will not raise on IO failures.
    """
    d = ensure_reports_dir(reports_dir)
    log_path = d / 'runtime_events.log'
    csv_path = d / 'runtime_events.csv'
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event, default=str) + '\n')
    except Exception:
        pass

    # update companion CSV
    core = ['timestamp', 'file_path', 'event_type', 'old_hash', 'new_hash', 'severity']
    try:
        write_header = not csv_path.exists()
        with open(csv_path, 'a', newline='', encoding='utf-8') as cf:
            writer = csv.DictWriter(cf, fieldnames=core)
            if write_header:
                writer.writeheader()
            row = {k: event.get(k, '') for k in core}
            writer.writerow(row)
    except Exception:
        pass

    return True

