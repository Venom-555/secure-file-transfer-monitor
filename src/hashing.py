"""Hashing helpers using standard library cryptography (SHA256).

This module centralizes file hashing and safe file reads so other
components don't duplicate error handling.
"""
from pathlib import Path
import hashlib
from typing import Optional


def calculate_sha256(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """Return SHA256 hex digest for `file_path` or None on error.

    Handles permission and IO errors gracefully.
    """
    p = Path(file_path)
    try:
        h = hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None
    except Exception:
        return None
