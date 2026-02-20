import json
import os
import time
import threading


class AttackLogger:
    """
    Logs completed attack sessions to:
    1️⃣ Local JSONL file (dashboard consumption)
    2️⃣ Optional blockchain logger
    """

    def __init__(
        self,
        log_file="logs/attack_summary_log.jsonl",
        blockchain_logger=None
    ):
        self.log_file = log_file
        self.blockchain_logger = blockchain_logger
        self.lock = threading.RLock()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    # ---------------------------------------------------------
    # Log Completed Attack Session
    # ---------------------------------------------------------
    def log_session(self, session):
        from blockchain_module.scripts.realtime_store_log import store_realtime_log
        attack_record = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.localtime(session["end_time"])
            ),
            "src_ip": session["ip"],
            "attack_type": session["attack_type"],
            "confidence": session["confidence"],
            "duration_seconds": session["duration"],
            "packet_count": session["packet_count"]
        }

        # 1️⃣ Write to local JSONL file
        with self.lock:
            try:
                with open(self.log_file, "a") as f:
                    f.write(json.dumps(attack_record) + "\n")
            except Exception as e:
                print("[ATTACK LOGGER ERROR - FILE]", e)

        # 2️⃣ Send to blockchain (CALL YOUR OLD SCRIPT)
        try:
            tx_hash = store_realtime_log(attack_record)
            attack_record["tx_hash"] = tx_hash
        except Exception as e:
            print("[BLOCKCHAIN ERROR]", e)

        return attack_record

