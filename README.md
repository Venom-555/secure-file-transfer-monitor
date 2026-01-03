# Secure File Transfer Monitoring System

## 📌 Project Overview
This project monitors secure file transfers by verifying file integrity using cryptographic hashing.
It detects unauthorized file modification, deletion, or creation in real time.

The system performs:
• Startup baseline integrity scan
• Real-time file system monitoring
• Severity-based alerting
• Automated report generation

## 🎯 Purpose
To ensure files transferred across systems arrive securely and remain untampered.

## 🛠 Technologies Used
- Python 3
- hashlib (SHA256)
- watchdog
- argparse
- CSV / JSON reporting

## ▶️ Quickstart — Install & Run

1. Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

2. Prepare runtime directories (create `data/` and `reports/`):

```bash
mkdir -p data reports logs
touch data/hash_db.json
```

3. Run the monitor (no daemonization; Ctrl+C to stop):

```bash
python3 run_monitor.py
```

Optional arguments for `run_monitor.py`:

- `--baseline-path` : write/read baseline JSON (defaults to `baseline.json`)
- `--reports-dir` : directory to write reports into (defaults to `reports/`)
- `--no-schedule` : do not start the daily report scheduler

Example using custom locations:

```bash
python3 run_monitor.py --baseline-path=data/baseline.json --reports-dir=reports/
```

4. Expected output files (created by the program):

- `baseline.json` — baseline file with path → hash/size/timestamp mappings
- `reports/startup_report.txt` — human-readable startup summary
- `reports/runtime_events.log` — newline-delimited JSON runtime events

Notes:
- The monitor performs a full recursive startup scan of configured watch paths,
	records SHA256 hashes for existing files into `baseline.json`, then begins
	real-time monitoring of create/modify/delete/rename events and appends
	structured event entries to `reports/runtime_events.log`.
- The repository does not automatically run anything; follow the commands above
	to execute locally in a controlled environment.


