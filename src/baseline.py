"""Baseline scanning utilities.

Provides a small helper to create a baseline JSON mapping canonical paths
to metadata including SHA256 hash and size.
"""
from pathlib import Path
from typing import Iterable, Dict, Tuple
from datetime import datetime
import json
from hashing import calculate_sha256


def generate_baseline(paths: Iterable[str], baseline_path: str = 'baseline.json') -> Tuple[Dict[str, dict], dict]:
    """Scan `paths` recursively and write baseline JSON to `baseline_path`.

    Returns (baseline_dict, summary)
    """
    baseline = {}
    total = 0
    for p in paths:
        root = Path(p)
        if not root.exists():
            continue
        for f in root.rglob('*'):
            if f.is_file():
                total += 1
                h = calculate_sha256(str(f))
                try:
                    size = f.stat().st_size
                except Exception:
                    size = 0
                baseline[str(f.resolve())] = {
                    'hash': h,
                    'size': size,
                    'first_seen': datetime.now().isoformat()
                }

    # persist
    try:
        p = Path(baseline_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, 'w', encoding='utf-8') as bf:
            json.dump(baseline, bf, indent=2)
    except Exception:
        pass

    summary = {'total_files': total, 'hashes_recorded': len(baseline), 'status': 'BASELINE_CREATED', 'timestamp': datetime.now().isoformat()}
    return baseline, summary
