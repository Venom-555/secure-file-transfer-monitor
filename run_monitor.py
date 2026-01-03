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
    parser = argparse.ArgumentParser(description="Run the Secure File Transfer Monitor")
    parser.add_argument('--baseline-path', help='Path to write/read baseline JSON (baseline.json)', default=None)
    parser.add_argument('--reports-dir', help='Directory to write reports into (reports/)', default=None)
    parser.add_argument('--no-schedule', help='Do not start daily report scheduler', action='store_true')
    args = parser.parse_args()

    # Start scheduler (runs at 02:00 by default) unless disabled
    if not args.no_schedule:
        schedule_daily_report(hour=2, minute=0)

    monitor.main(baseline_path=args.baseline_path, reports_dir=args.reports_dir)
