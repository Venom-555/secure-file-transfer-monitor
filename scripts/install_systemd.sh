#!/usr/bin/env bash
set -euo pipefail

# Installs a user-level systemd service for the Secure File Transfer Monitor.
# Usage: ./scripts/install_systemd.sh

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$PROJECT_DIR/scripts/secure_monitor.service.template"
SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/secure_monitor.service"

mkdir -p "$SERVICE_DIR"

PYTHON="$PROJECT_DIR/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3 || echo python)"
fi

sed "s|{{PYTHON}}|$PYTHON|g; s|{{PROJECT_DIR}}|$PROJECT_DIR|g" "$TEMPLATE" > "$SERVICE_FILE"

echo "Installed service to $SERVICE_FILE"
echo "Reloading user systemd and enabling service..."
systemctl --user daemon-reload
systemctl --user enable --now secure_monitor.service

echo "Service enabled and started. Check status with: systemctl --user status secure_monitor.service"
