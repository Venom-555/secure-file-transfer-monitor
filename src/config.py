"""Configuration handler for the monitoring system.

This module intentionally uses only the Python standard library. The
configuration file is stored as JSON under `config/config.json`.
"""
import json
from pathlib import Path
from typing import Any, Dict


class Config:
    """Load and expose configuration values with sane defaults."""

    def __init__(self, config_path: str = "config/config.json"):
        self.config_path = Path(config_path)
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        default_config = {
            "monitoring": {
                "watch_paths": [
                    "watch_dir"
                ],
                "recursive": True,
                "poll_interval": 1
            },
            "security": {
                "sensitive_directories": ["/etc", "/home/secure"],
                "restricted_extensions": [".exe", ".dll", ".bat", ".ps1"],
                "authorized_users": ["root", "admin"]
            },
            "integrity": {
                "hash_database": "data/hash_db.json",
                "hash_algorithm": "sha256"
            },
            "alerts": {
                "enabled": True,
                "email_alerts": False,
                "alerts_log": "logs/alerts.log",
                "minimum_severity": "MEDIUM"
            },
            "logging": {
                "transfer_log": "logs/file_transfer.log",
                "log_level": "INFO",
                "max_log_size_mb": 10
            },
            "reporting": {
                "generate_daily_reports": True,
                "report_directory": "reports/"
            }
        }

        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    user = json.load(f) or {}
                    self._merge(default_config, user)
                    return default_config
            except Exception:
                return default_config
        else:
            # create default config JSON for users to edit
            try:
                self.config_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
            except Exception:
                pass
            return default_config

    def _merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for k, v in (override or {}).items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def get_watch_paths(self):
        return self.config["monitoring"]["watch_paths"]

    def get_sensitive_directories(self):
        return self.config["security"]["sensitive_directories"]

    def get_restricted_extensions(self):
        return self.config["security"]["restricted_extensions"]

    def get_hash_database_path(self):
        return self.config["integrity"]["hash_database"]

    def get_alerts_log_path(self):
        return self.config["alerts"]["alerts_log"]

    def get_email_alerts_enabled(self):
        return self.config["alerts"].get("email_alerts", False)

    def get_smtp_config(self):
        return self.config.get("smtp", {})

    def save_config(self):
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass