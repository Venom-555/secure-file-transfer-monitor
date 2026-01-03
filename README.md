# Secure File Transfer Monitoring System

Purpose
-------
Lightweight file transfer integrity monitoring for security auditing and
portfolio demonstration. The project performs an initial baseline of file
hashes and then monitors directories in real time for CREATE / MODIFY / DELETE
/ MOVE events, scoring severity and persisting structured reports.

Requirements
------------
- Python 3.8+
- Linux or Windows
- Minimal external dependency: `watchdog` (listed in `requirements.txt`)

Install
-------
Install the runtime dependency:

```bash
python3 -m pip install -r requirements.txt
```

Quickstart
----------
Create a baseline (one-shot scan):

```bash
python3 run_monitor.py --baseline --watch-dir watch_dir --output reports
```

Start real-time monitoring:

```bash
python3 run_monitor.py --monitor --output reports
```

CLI Flags
---------
- `--baseline`: perform an initial recursive scan and save `baseline.json`.
- `--monitor`: start the watchdog-based real-time monitor loop.
- `--watch-dir`: override watch paths from the config with a single directory.
- `--output`: specify the `reports/` directory to write JSON/CSV outputs.

Example outputs
---------------
Reports are written to the configured `reports/` directory. Example JSON record:

```json
{
	"timestamp": "2026-01-03T22:01:07.478206",
	"file_path": "/abs/path/watch_dir/testfile.txt",
	"event_type": "MODIFIED",
	"old_hash": "",
	"new_hash": "3a7bd3e2360a...",
	"severity": "MEDIUM"
}
```

Companion CSV rows are written with columns: `timestamp,file_path,event_type,old_hash,new_hash,severity`.

Architecture
------------
- `src/hashing.py` — SHA256 hashing helper with safe IO handling.
- `src/baseline.py` — recursive baseline scanner that writes `baseline.json`.
- `src/integrity_checker.py` — orchestrates integrity checks and baseline persistence.
- `src/monitor.py` — watchdog event handler, compares hashes and emits events.
- `src/reporter.py` — writes JSON and CSV reports into `reports/`.
- `src/severity.py` — maps events and integrity outcomes to severity levels.
- `src/config.py` — JSON-based configuration loader with sensible defaults.
- `src/logger.py` — file-based JSON logging and CSV summaries.
- `src/alert_system.py` — lightweight alert logging and console notifications.

Security Use Cases
------------------
- Detect tampering or corruption after file transfer into monitored directories.
- Alert on unexpected deletions of protected files (CRITICAL severity).
- Produce auditable artifacts (CSV/JSON) for incident response and review.

Platform notes
--------------
- Works on Linux and Windows; absolute paths are used for baseline keys.
- Ensure the process has permission to read files in the watched directories.

Testing and verification
-----------------------
Run the included basic baseline run locally:

```bash
python3 - <<'PY'
import sys
sys.path.insert(0,'./src')
from baseline import generate_baseline
generate_baseline(['watch_dir'], baseline_path='baseline.json')
PY
```

Then start the monitor and create/modify/delete files under `watch_dir` to see
events appended to `reports/runtime_events.log` and `reports/runtime_events.csv`.

Contributing
------------
PRs and issues welcome. Keep changes focused and include tests where applicable.

License
-------
MIT
# Secure File Transfer Monitoring System

Purpose
-------
This project monitors a directory tree for file transfers and changes, verifies integrity using SHA256, and generates structured reports suitable for security auditing and portfolio demonstrations.

Key features
------------
- Baseline scan mode to record canonical SHA256 hashes for all files.
- Real-time monitoring using `watchdog` (CREATE / MODIFY / DELETE / MOVE).
- Integrity verification and severity scoring (LOW / MEDIUM / HIGH / CRITICAL).
- Reports generated in CSV and JSON placed under `reports/`.
- Minimal external dependency surface: `watchdog` only.

Installation
------------
Requirements: Python 3.8+ and `pip`.

Install the single dependency:

```bash
python3 -m pip install -r requirements.txt
```

Usage
-----
Run the CLI script `run_monitor.py`.

Create baseline (one-shot):

```bash
python3 run_monitor.py --baseline --watch-dir watch_dir --output reports
```

Start monitor (real-time):

```bash
python3 run_monitor.py --monitor --output reports
```

CLI flags
- `--baseline`: perform initial recursive scan and save baseline.json
- `--monitor`: start real-time monitoring loop
- `--watch-dir`: override watch paths from config
- `--output`: set reports output directory

Architecture
------------
- `src/hashing.py`: file hashing utilities (SHA256)
- `src/baseline.py`: baseline scan helper
- `src/integrity_checker.py`: integrity check orchestration and baseline persistence
- `src/monitor.py`: watchdog integration and event processing
- `src/reporter.py`: JSON and CSV report generation
- `src/severity.py`: severity scoring logic
- `src/config.py`: configuration loader (JSON)
- `src/logger.py`: event logging to logs/ and CSV summaries
- `src/alert_system.py`: lightweight alert logging and console notifiers

Examples and outputs
--------------------
- Baseline writes `baseline.json` and `reports/baseline_<timestamp>.json|.csv`.
- Runtime events appended to `reports/runtime_events.log` and `reports/runtime_events.csv`.

Security use cases
------------------
- Verify that files transferred to a monitored directory remain unchanged.
- Alert on unexpected deletions or tampering of protected files.
- Provide auditable CSV/JSON reports for incident review and academic evaluation.

Contributing
------------
This project is organized for clarity and extensibility. Please open issues or PRs with enhancements or test cases.
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


