"""
File Collector — snapshot of files modified recently in the user's directories.

Read-only: only file metadata (path, size, extension) is collected, never contents.
Sensitivity is inferred from the extension/path (0 = low, 1 = medium, 2 = high).
(The original live watchdog monitor was removed: it blocked the API for 60 s.)
"""
from __future__ import annotations

import getpass
import os
import platform
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from tools.collectors.schema import StandardEvent, create_event

HIGH_SENS_EXT = {".pem", ".key", ".pfx", ".env", ".sql", ".bak", ".db", ".sqlite"}
MED_SENS_EXT = {".xlsx", ".docx", ".pdf", ".csv", ".pptx", ".json", ".xml"}
SENS_PATHS = ["financial", "hr", "confidential", "secret", "private", "credentials"]
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "AppData", "Library", ".cache"}


def infer_sensitivity(file_path: str) -> int:
    ext = Path(file_path).suffix.lower()
    lower = file_path.lower()
    if ext in HIGH_SENS_EXT or any(s in lower for s in SENS_PATHS):
        return 2
    return 1 if ext in MED_SENS_EXT else 0


def is_usb_path(file_path: str) -> bool:
    """True if the path is on a removable drive (Windows only)."""
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        drive = os.path.splitdrive(file_path)[0] + "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(drive) == 2  # DRIVE_REMOVABLE
    except Exception:
        return False


def collect_file_snapshot(scan_dirs: Optional[list[str]] = None, hours_back: int = 1,
                          max_depth: int = 3, max_events: int = 200) -> list[StandardEvent]:
    """Files modified in the last ``hours_back`` hours (default: the home folder)."""
    scan_dirs = scan_dirs or [os.path.expanduser("~")]
    user_id, device_id = getpass.getuser(), socket.gethostname()
    since = datetime.now() - timedelta(hours=hours_back)
    events: list[StandardEvent] = []
    for scan_dir in scan_dirs:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            if root[len(scan_dir):].count(os.sep) >= max_depth:
                dirs.clear()
            for name in files:
                path = os.path.join(root, name)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(path))
                    if mtime <= since:
                        continue
                    events.append(create_event(
                        event_type="file_access", event_category="file", action="modify", resource=path,
                        user_id=user_id, device_id=device_id, source="os_scan", timestamp=mtime.isoformat(),
                        file_path=path, file_extension=Path(path).suffix.lower(),
                        file_size_bytes=os.path.getsize(path), is_usb=is_usb_path(path),
                        sensitivity_level=infer_sensitivity(path),
                    ))
                except OSError:
                    continue
                if len(events) >= max_events:
                    return events
    return events
