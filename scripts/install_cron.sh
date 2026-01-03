#!/usr/bin/env bash
set -euo pipefail
# Installs a user cron job to run the project's report generator daily at 15:30

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3 || command -v python)"
fi

LOGFILE="$ROOT/logs/report_generator.log"
mkdir -p "$(dirname \"$LOGFILE\")"

CMD="$PY $ROOT/reports/generate_report.py --all >> $LOGFILE 2>&1"

echo "Installing cron job to run report daily at 15:30"

# Don't duplicate entry
crontab -l 2>/dev/null | grep -F "$ROOT/reports/generate_report.py" >/dev/null 2>&1 && {
  echo "Cron job already installed for this project.";
  exit 0;
}

# Install new cron line
(
  crontab -l 2>/dev/null || true
  echo "30 15 * * * $CMD"
) | crontab -

echo "Installed: 30 15 * * * $CMD"
echo "Logs will be appended to: $LOGFILE"
echo "To remove, run: crontab -l | grep -v '$ROOT/reports/generate_report.py' | crontab -"
