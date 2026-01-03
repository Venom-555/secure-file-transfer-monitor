#!/usr/bin/env python3
"""Run the monitor with `src` on the import path and schedule daily reports.

This file will prefer the project's `.venv` Python if present. If not already
running from the virtualenv, it will re-exec the script with the venv Python so
environment isolation is maintained.
"""
import os
import sys
import time
import threading
import subprocess
from pathlib import Path

# If a `.venv` exists in the project and we're not running inside it, re-exec
# with the virtualenv python to ensure dependencies are available.
PROJECT_ROOT = Path(__file__).parent
VENV_PY = PROJECT_ROOT / '.venv' / 'bin' / 'python'
if not os.environ.get('VIRTUAL_ENV') and VENV_PY.exists():
    try:
        # Avoid an infinite re-exec loop if already using the correct interpreter
        if Path(sys.executable) != VENV_PY:
            os.execv(str(VENV_PY), [str(VENV_PY), str(Path(__file__).absolute()), *sys.argv[1:]])
    except Exception:
        # If exec fails, fall back to the current interpreter and continue.
        pass

# Ensure `src` directory is first on sys.path so local modules are importable
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Helpful dependency check: if `watchdog` is missing, print instructions
try:
    import watchdog  # noqa: F401
except Exception:
    venv_python = VENV_PY
    pip_cmd = f"{venv_python} -m pip install -r requirements.txt" if venv_python.exists() else "python3 -m pip install -r requirements.txt"
    print("Missing dependency: `watchdog`. Install project requirements with:")
    print(f"  {pip_cmd}")
    raise

import argparse
import monitor
from reporter import write_report_records


def _seconds_until(hour=2, minute=0):
    """Return seconds until next occurrence of hour:minute local time."""
    from datetime import datetime, timedelta
    now = datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target = target + timedelta(days=1)
    return (target - now).total_seconds()


def schedule_daily_report(hour=2, minute=0, script_path=None):
    """Run the report generator daily at the given hour:minute.

    This launches `python reports/generate_report.py --all` in a subprocess.
    """
    script = script_path or (Path(__file__).parent / 'reports' / 'generate_report.py')

    def _runner():
        env = None
        try:
            import os
            env = os.environ.copy()
            env['PYTHONPATH'] = str(Path(__file__).parent / 'src')
        except Exception:
            env = None

        while True:
            seconds = _seconds_until(hour, minute)
            time.sleep(seconds)
            try:
                subprocess.run([sys.executable, str(script), '--all'], check=False, env=env)
            except Exception:
                pass

    t = threading.Thread(target=_runner, daemon=True, name='daily-report-scheduler')
    t.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Transfer Monitoring CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--baseline', help='Run baseline scan and generate baseline.json', action='store_true')
    group.add_argument('--monitor', help='Start real-time monitor', action='store_true')
    parser.add_argument('--watch-dir', help='Directory to watch (overrides config)', default=None)
    parser.add_argument('--output', help='Reports directory (overrides config)', default=None)
    parser.add_argument('--no-schedule', help='Do not start daily report scheduler', action='store_true')
    args = parser.parse_args()

    if args.output:
        import os
        os.environ['REPORTS_DIR'] = args.output

    # Baseline mode: perform a one-shot baseline scan and produce reports
    if args.baseline:
        # If user provided watch-dir, scan that; otherwise use config
        if args.watch_dir:
            watch_paths = [args.watch_dir]
        else:
            from config import Config as _C  # local import after sys.path arranged
            watch_paths = _C().get_watch_paths()

        from baseline import generate_baseline
        baseline, summary = generate_baseline(watch_paths, baseline_path='baseline.json')
        # write startup report and also structured reports
        from reporter import write_startup_report, write_report_records
        write_startup_report(summary, baseline, reports_dir=args.output)
        # Create individual records for report pipeline
        records = []
        for path, meta in baseline.items():
            records.append({
                'timestamp': summary.get('timestamp'),
                'file_path': path,
                'event_type': 'BASELINE',
                'old_hash': '',
                'new_hash': meta.get('hash'),
                'severity': 'LOW'
            })
        write_report_records(records, reports_dir=args.output, prefix='baseline')
        print('Baseline scan complete')
        raise SystemExit(0)

    # Monitor mode
    if args.monitor:
        if not args.no_schedule:
            schedule_daily_report(hour=2, minute=0)
        # pass baseline path if provided via --watch-dir? Keep default behavior
        monitor.main(baseline_path=None, reports_dir=args.output)
