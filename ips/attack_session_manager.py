import time
import threading
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
    
class AttackSessionManager:

    def __init__(self, attack_logger=None, session_timeout=10):
        self.active_sessions = {}
        self.completed_sessions = []
        self.lock = threading.RLock()
        self.session_timeout = session_timeout
        self.attack_logger = attack_logger

    # ---------------------------------------------------------
    # Start or Update Session
    # ---------------------------------------------------------
    def start_or_update_session(self, ip, attack_type, confidence):

        now = time.time()

        with self.lock:

            if ip not in self.active_sessions:
                print(f"[SESSION START] {ip} → {attack_type}")

                self.active_sessions[ip] = {
                    "ip": ip,
                    "attack_type": attack_type,
                    "start_time": now,
                    "last_seen": now,
                    "confidence": confidence,
                    "packet_count": 1
                }

            else:
                session = self.active_sessions[ip]
                session["last_seen"] = now
                session["packet_count"] += 1

                # Upgrade attack type if needed
                if attack_type != session["attack_type"]:
                    print(f"[SESSION UPDATE] {ip} → {attack_type}")
                    session["attack_type"] = attack_type

    # ---------------------------------------------------------
    # Expire Sessions (called from expiry engine)
    # ---------------------------------------------------------
    def expire_sessions(self):

        now = time.time()

        with self.lock:

            expired = []

            for ip, session in self.active_sessions.items():
                if now - session["last_seen"] > self.session_timeout:
                    expired.append(ip)

            for ip in expired:

                session = self.active_sessions[ip]
                session["end_time"] = now
                session["duration"] = round(
                    now - session["start_time"], 2
                )

                print(f"[SESSION END] {ip} | "
                      f"{session['attack_type']} | "
                      f"Duration: {session['duration']}s")

                self.completed_sessions.append(dict(session))

                # Unified Logger Hook
                if self.attack_logger:
                    try:
                        self.attack_logger.log_session(session)
                    except Exception as e:
                        print("[ATTACK LOGGER ERROR]", e)

                del self.active_sessions[ip]

    # ---------------------------------------------------------
    # For Dashboard API
    # ---------------------------------------------------------
    def get_completed_sessions(self):
        with self.lock:
            return list(self.completed_sessions)
