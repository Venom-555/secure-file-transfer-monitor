"""Severity scoring for file integrity and transfer events.

Provides a clear mapping from event types and integrity results to
severity labels used in reports and alerts.
"""
from typing import Optional


def score_severity(event_type: str, integrity_status: Optional[str], is_protected: bool) -> str:
    """Return one of LOW/MEDIUM/HIGH/CRITICAL based on inputs.

    - LOW: new file created or informational
    - MEDIUM: modified file (non-destructive)
    - HIGH: corruption or hash mismatch
    - CRITICAL: deleted protected file (sensitive/protected)
    """
    status = (integrity_status or '').upper()

    if status == 'DELETED' and is_protected:
        return 'CRITICAL'
    if status in ('CORRUPTED', 'INTEGRITY_FAILED', 'MISMATCH'):
        return 'HIGH'
    if event_type.upper() in ('MODIFIED', 'MOVED') or status == 'MODIFIED':
        return 'MEDIUM'
    if event_type.upper() in ('CREATED',) or status.startswith('NEW'):
        return 'LOW'
    return 'LOW'
