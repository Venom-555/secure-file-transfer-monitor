"""
File Integrity Checker using SHA256 hashing
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime
from config import Config

class IntegrityChecker:
    """Handles file integrity checks using cryptographic hashing"""
    
    def __init__(self):
        self.config = Config()
        self.hash_db_file = self.config.get_hash_database_path()
        # Internal persistent hash DB (used by older codepaths)
        self.hash_db = self.load_hash_database()
        # Baseline (startup scan) stored separately in `baseline.json` by default
        self.baseline_path = Path('baseline.json')
        self.baseline = self.load_baseline()
    
    def calculate_hash(self, file_path, algorithm='sha256'):
        """Calculate hash of a file"""
        try:
            hash_func = getattr(hashlib, algorithm)()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def check_file(self, file_path):
        """Check file integrity against stored hash"""
        result = {
            "file": str(file_path),
            "timestamp": datetime.now().isoformat(),
            "status": "UNKNOWN",
            "current_hash": None,
            "stored_hash": None,
            "match": False
        }
        
        current_hash = self.calculate_hash(file_path)
        if not current_hash:
            result["status"] = "ERROR"
            return result
        
        result["current_hash"] = current_hash
        
        # Prefer baseline for integrity comparisons if available
        file_key = str(Path(file_path).resolve())
        if file_key in self.baseline:
            result["stored_hash"] = self.baseline[file_key].get("hash")
            result["match"] = current_hash == result["stored_hash"]
            result["status"] = "MATCH" if result["match"] else "MISMATCH"
            if not result["match"]:
                print(f"⚠️  Integrity mismatch detected for: {file_path}")
        elif file_key in self.hash_db:
            # fallback to legacy DB
            result["stored_hash"] = self.hash_db[file_key]["hash"]
            result["match"] = current_hash == result["stored_hash"]
            result["status"] = "MATCH" if result["match"] else "MISMATCH"
            if not result["match"]:
                print(f"⚠️  Integrity mismatch detected for: {file_path}")
        else:
            # New file -- register in both baseline and legacy DB
            ts = datetime.now().isoformat()
            self.baseline[file_key] = {
                "hash": current_hash,
                "size": Path(file_path).stat().st_size if Path(file_path).exists() else 0,
                "first_seen": ts,
                "last_checked": ts
            }
            # Also keep legacy DB in sync
            self.hash_db[file_key] = {"hash": current_hash, "first_seen": ts, "last_checked": ts}
            self.save_hash_database()
            self.save_baseline()
            result["status"] = "NEW_FILE_REGISTERED"
        
        return result
    
    def store_baseline_hash(self, file_path):
        """Store baseline hash for a file"""
        hash_value = self.calculate_hash(file_path)
        if hash_value:
            file_key = str(Path(file_path).resolve())
            self.hash_db[file_key] = {
                "hash": hash_value,
                "first_seen": datetime.now().isoformat(),
                "last_checked": datetime.now().isoformat()
            }
            self.save_hash_database()
            return True
        return False

    # ----- Baseline handling -----
    def generate_baseline(self, directory_paths, baseline_path=None):
        """Recursively scan directories and create a baseline JSON file.

        directory_paths: list of paths to scan
        baseline_path: optional path to write baseline (defaults to `baseline.json`)
        Returns a dict with scan summary and the baseline dict.
        """
        if baseline_path:
            self.baseline_path = Path(baseline_path)

        baseline = {}
        total = 0
        for dp in directory_paths:
            p = Path(dp)
            if not p.exists():
                continue
            for f in p.rglob('*'):
                if f.is_file():
                    total += 1
                    h = self.calculate_hash(f)
                    try:
                        size = f.stat().st_size
                    except Exception:
                        size = 0
                    baseline[str(f.resolve())] = {
                        'hash': h,
                        'size': size,
                        'first_seen': datetime.now().isoformat()
                    }

        self.baseline = baseline
        self.save_baseline()
        # Keep legacy DB in sync for quick lookups
        for k, v in baseline.items():
            if k not in self.hash_db:
                self.hash_db[k] = {'hash': v.get('hash'), 'first_seen': v.get('first_seen'), 'last_checked': v.get('first_seen')}
        self.save_hash_database()

        summary = {'total_files': total, 'hashes_recorded': len(baseline), 'status': 'BASELINE_CREATED', 'timestamp': datetime.now().isoformat()}
        return summary, baseline

    def load_baseline(self, baseline_path=None):
        """Load baseline JSON from file if present."""
        path = Path(baseline_path) if baseline_path else self.baseline_path
        try:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def save_baseline(self, baseline_path=None):
        """Save the current baseline to disk."""
        path = Path(baseline_path) if baseline_path else self.baseline_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.baseline, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving baseline: {e}")
            return False
    
    def verify_directory(self, directory_path):
        """Verify integrity of all files in a directory"""
        results = []
        directory = Path(directory_path)
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                result = self.check_file(file_path)
                results.append(result)
        
        return results
    
    def load_hash_database(self):
        """Load hash database from file"""
        try:
            p = Path(self.hash_db_file)
            if p.exists():
                with open(p, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading hash database: {e}")
        
        return {}
    
    def save_hash_database(self):
        """Save hash database to file"""
        try:
            p = Path(self.hash_db_file)
            # Ensure parent directory exists before writing
            if not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(self.hash_db, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving hash database: {e}")
            return False
    
    def generate_integrity_report(self, directory_path=None):
        """Generate integrity report"""
        if directory_path:
            results = self.verify_directory(directory_path)
        else:
            results = []
            for file_key in self.hash_db.keys():
                result = self.check_file(file_key)
                results.append(result)
        
        # Generate summary
        summary = {
            "total_files": len(results),
            "matches": sum(1 for r in results if r.get("match") is True),
            "mismatches": sum(1 for r in results if r.get("match") is False),
            "errors": sum(1 for r in results if r["status"] == "ERROR"),
            "new_files": sum(1 for r in results if r["status"] == "NEW_FILE_REGISTERED")
        }
        
        return {
            "summary": summary,
            "details": results,
            "timestamp": datetime.now().isoformat()
        }
    