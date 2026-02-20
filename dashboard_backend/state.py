# dashboard_backend/state.py

from datetime import datetime
from collections import Counter,defaultdict
import os
import json

# 🔴 CHANGE ONLY THIS IF YOUR WINDOWS PATH IS DIFFERENT
STATUS_FILE = r"D:\IDS-hybrid\ips\logs\system_status.json"

def read_status():
    """
    Reads IPS system status file written by Ubuntu VM.
    Returns safe fallback if file not available.
    """

    if not os.path.exists(STATUS_FILE):
        return {
            "system_state": "OFFLINE",
            "blocked_ips": [],
            "active_blocks": {}
        }

    try:
        with open(STATUS_FILE, "r") as f:
            data = json.load(f)

        # Safety check in case file is partially written
        return {
            "system_state": data.get("system_state", "UNKNOWN"),
            "blocked_ips": data.get("blocked_ips", []),
            "active_blocks": data.get("active_blocks", {})
        }

    except Exception:
        return {
            "system_state": "ERROR",
            "blocked_ips": [],
            "active_blocks": {}
        }

ATTACK_LOG_FILE = r"D:\IDS-hybrid\ips\logs\attack_summary_log.jsonl"


def read_recent_attacks(limit=50):
    if not os.path.exists(ATTACK_LOG_FILE):
        return []

    try:
        with open(ATTACK_LOG_FILE, "r") as f:
            lines = f.readlines()[-limit:]

        return [json.loads(line.strip()) for line in lines]

    except Exception:
        return []
    

def get_attack_distribution():
    attacks = read_recent_attacks(limit=200)

    counter = Counter()

    for attack in attacks:
        attack_type = attack.get("attack_type")
        if attack_type:
            counter[attack_type] += 1

    return dict(counter)


def get_attack_timeline():
    attacks = read_recent_attacks(limit=500)

    timeline = defaultdict(int)

    for attack in attacks:
        ts = attack.get("timestamp")
        if not ts:
            continue

        try:
            # Format example: 2026-02-20T21:30:15
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
            minute_key = dt.strftime("%Y-%m-%d %H:%M")
            timeline[minute_key] += 1
        except Exception:
            continue

    # Sort by time
    sorted_timeline = sorted(timeline.items())

    return [
        {"timestamp": t, "count": c}
        for t, c in sorted_timeline
    ]



BLOCKCHAIN_STATUS_FILE = r"D:\IDS-hybrid\ips\logs\blockchain_status.json"

def read_blockchain_status():
    if not os.path.exists(BLOCKCHAIN_STATUS_FILE):
        return {"connected": False, "block_number": None}

    try:
        with open(BLOCKCHAIN_STATUS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"connected": False, "block_number": None}
    

LIVE_ATTACK_FILE = r"D:\IDS-hybrid\ips\logs\live_attacks.json"

def read_live_attacks():
    if not os.path.exists(LIVE_ATTACK_FILE):
        return []

    try:
        with open(LIVE_ATTACK_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []