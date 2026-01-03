"""
Configuration handler for the monitoring system
"""

import yaml
from pathlib import Path


class Config:
    """Handles configuration loading and management"""

    def __init__(self, config_path="config/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from YAML file"""
        default_config = {
            "monitoring": {
                "watch_paths": [
                    "/var/log",
                    "/tmp"
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
                with open(self.config_path, "r", encoding="utf-8") as f:
                    user_config = yaml.safe_load(f) or {}
                    return self.merge_configs(default_config, user_config)
            except Exception:
                return default_config
        else:
            self.create_default_config(default_config)
            return default_config

    def merge_configs(self, default, user):
        """Merge default and user configurations"""
        merged = default.copy()

        def merge_dicts(d1, d2):
            for key, value in (d2 or {}).items():
                if key in d1 and isinstance(d1[key], dict) and isinstance(value, dict):
                    merge_dicts(d1[key], value)
                else:
                    d1[key] = value

        merge_dicts(merged, user)
        return merged

    def create_default_config(self, config):
        """Create default configuration file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False)

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
        return self.config["alerts"]["email_alerts"]

    def get_smtp_config(self):
        return self.config.get("smtp", {})

    def save_config(self):
        """Save current configuration to file"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self.config, f, default_flow_style=False)