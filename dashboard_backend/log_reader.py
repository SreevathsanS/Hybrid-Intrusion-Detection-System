# dashboard_backend/log_reader.py

import os
import json
from dashboard_backend.config import LOG_FILE, MAX_LOG_LINES


def read_recent_logs():
    """
    Reads last N attack logs from JSONL file
    """

    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()[-MAX_LOG_LINES:]

    return [json.loads(line.strip()) for line in lines]