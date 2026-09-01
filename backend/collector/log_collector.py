"""
log_collector.py - Reads raw log files from disk.

Responsibility: File I/O only.
The collector does NOT parse or interpret log content.
It simply reads lines and passes them to the normalizer.
This separation of concerns mirrors real SIEM architecture (e.g., Filebeat in the ELK stack).
"""

import os
from typing import Generator, Tuple

# Resolve path relative to this file so it works regardless of working directory
SAMPLE_LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_logs")

LOG_FILES = {
    "authentication": "auth.log",
    "web": "web.log",
    "network": "network.log",
}


def collect_raw_logs() -> Generator[Tuple[str, str], None, None]:
    """
    Yields (source_name, raw_line) tuples for every non-empty line in every log file.
    Skips missing files gracefully - a real SIEM must handle unavailable log sources.
    """
    for source, filename in LOG_FILES.items():
        filepath = os.path.join(SAMPLE_LOGS_DIR, filename)
        if not os.path.exists(filepath):
            print(f"[COLLECTOR] Warning: {filepath} not found, skipping.")
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield source, line
