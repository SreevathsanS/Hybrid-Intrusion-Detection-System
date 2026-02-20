import time
import threading
import json


class BlockManager:
    def __init__(self, block_duration=10, 
        cooldown_duration=30, 
        log_file="ips_logs.json",
        attack_session_manager=None,
        behavior_engine=None,       
        volumetric_engine=None,
        flow_manager = None 
        ):

        self.block_duration = block_duration
        self.attack_session_manager = attack_session_manager
        self.behavior_engine = behavior_engine       # ADD THIS
        self.volumetric_engine = volumetric_engine   # ADD THIS
        self.flow_manager = flow_manager
        self.log_file = log_file

        self.blocked_ips = {}
        self.cooldown_duration = cooldown_duration
        self.lock = threading.RLock()
        self.cooldown_ips = {}

        self.system_state = "IDLE"

        self.attack_priority = {
            "DDoS_PPS": 5,
            "DDoS_BPS": 5,
            "SYN_FLOOD": 4,
            "PORT_SCAN": 3,
            "CONNECTION_BURST": 3,
            "FORWARD_ONLY_FLOOD": 3,
            "ML_ATTACK": 4
        }

    # ---------------------------------------------------------
    def block_ip(self, ip, attack_type, confidence=1.0):
        now = time.time()

        with self.lock:

            # 🚫 If IP is in cooldown → ignore
            if ip in self.cooldown_ips:
                if now < self.cooldown_ips[ip]:
                    return
                else:
                    del self.cooldown_ips[ip]

            # 🔁 If already blocked → extend block
            if ip in self.blocked_ips:
                self.blocked_ips[ip]["unblock_time"] = now + self.block_duration
                return

            print(f"[BLOCK] {ip} → {attack_type}")

            self.blocked_ips[ip] = {
                "unblock_time": now + self.block_duration,
                "attack_type": attack_type
            }

            self._log_event(ip, attack_type, confidence)

            if self.system_state == "IDLE":
                print("SYSTEM UNDER ATTACK")
                self.system_state = "UNDER_ATTACK"

            self._clear_engine_state(ip)

            if self.attack_session_manager:
                self.attack_session_manager.start_or_update_session(
                    ip,
                    attack_type,
                    confidence
                )


    # ---------------------------------------------------------
    def expire_blocks(self):
        now = time.time()

        with self.lock:
            expired = [
                ip for ip, data in self.blocked_ips.items()
                if now >= data["unblock_time"]
            ]

            for ip in expired:
                print(f"[UNBLOCK] {ip}")
                self.cooldown_ips[ip] = now + self.cooldown_duration
                del self.blocked_ips[ip]

            if self.system_state == "UNDER_ATTACK" and not self.blocked_ips:
                print("SYSTEM BACK TO IDLE")
                self.system_state = "IDLE"

    # ---------------------------------------------------------
    def is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked_ips

    # ---------------------------------------------------------
    def _log_event(self, ip, attack_type, confidence):
        log_entry = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.localtime()
            ),
            "source_ip": ip,
            "attack_type": attack_type,
            "confidence": confidence,
            "block_duration": self.block_duration
        }

        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass
    
    def _clear_engine_state(self, ip):
        try:
            if self.behavior_engine:
                with self.behavior_engine.lock:
                    self.behavior_engine.source_activity.pop(ip, None)
        except Exception as e:
            print(f"[BLOCK MANAGER] Failed to clear behavior state: {e}")

        try:
            if self.volumetric_engine:
                with self.volumetric_engine.lock:
                    self.volumetric_engine.source_stats.pop(ip, None)
        except Exception as e:
            print(f"[BLOCK MANAGER] Failed to clear volumetric state: {e}")

        # ADD: clear any buffered flows for this IP
        try:
            if self.flow_manager:
                with self.flow_manager.lock:
                    keys_to_delete = [
                        k for k in self.flow_manager.flow_table
                        if k[0] == ip  # src_ip is first element of flow key tuple
                    ]
                    for k in keys_to_delete:
                        del self.flow_manager.flow_table[k]
        except Exception as e:
            print(f"[BLOCK MANAGER] Failed to clear flow state: {e}")