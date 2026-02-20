import time
import threading


class BehaviorEngine:
    def __init__(
        self,
        window_size=5,
        port_scan_threshold=25,
        connection_burst_threshold=150
    ):
        self.window_size = window_size
        self.port_scan_threshold = port_scan_threshold
        self.connection_burst_threshold = connection_burst_threshold

        self.source_activity = {}
        self.lock = threading.RLock()

    # ---------------------------------------------------------
    # Main check function (called per packet)
    # ---------------------------------------------------------
    def check(self, packet_info):
        """
        packet_info = {
            src_ip,
            dst_port,
            timestamp
        }
        """

        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]
        now = packet_info["timestamp"]

        with self.lock:
            if src_ip not in self.source_activity:
                self.source_activity[src_ip] = {
                    "ports": [],
                    "connections": []
                }

            activity = self.source_activity[src_ip]

            # Add new activity
            activity["ports"].append((dst_port, now))
            activity["connections"].append(now)

            # Remove old entries outside sliding window
            self._prune(activity, now)

            # -------------------------
            # Port Scan Detection
            # -------------------------
            unique_ports = {p for p, _ in activity["ports"]}

            if len(unique_ports) >= self.port_scan_threshold:
                return True, "PORT_SCAN"

            # -------------------------
            # Connection Burst Detection
            # -------------------------
            if len(activity["connections"]) >= self.connection_burst_threshold:
                return True, "CONNECTION_BURST"

        return False, None

    # ---------------------------------------------------------
    # Prune old entries
    # ---------------------------------------------------------
    def _prune(self, activity, now):
        cutoff = now - self.window_size

        activity["ports"] = [
            (port, ts) for port, ts in activity["ports"]
            if ts >= cutoff
        ]

        activity["connections"] = [
            ts for ts in activity["connections"]
            if ts >= cutoff
        ]

    # ---------------------------------------------------------
    # Optional cleanup for memory safety
    # ---------------------------------------------------------
    def expire_sources(self):
        now = time.time()
        cutoff = now - self.window_size

        with self.lock:
            expired_ips = []

            for ip, activity in self.source_activity.items():
                if not activity["connections"]:
                    expired_ips.append(ip)
                    continue

                if max(activity["connections"]) < cutoff:
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self.source_activity[ip]
