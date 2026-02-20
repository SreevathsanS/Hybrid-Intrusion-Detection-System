import time
import threading
import numpy as np

class HostAggregator:

    def __init__(self, window_size=10):
        self.window_size = window_size
        self.host_table = {}
        self.lock = threading.RLock()

    def update(self, packet_info):

        src_ip = packet_info["src_ip"]
        now = packet_info["timestamp"]

        with self.lock:
            if src_ip not in self.host_table:
                self.host_table[src_ip] = {
                    "start_time": now,
                    "last_seen": now,
                    "total_packets": 0,
                    "total_bytes": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "rst_count": 0,
                    "psh_count": 0,
                    "iat_list": [],
                    "packet_times": []
                }

            host = self.host_table[src_ip]

            # Update time
            if host["last_seen"] is not None:
                iat = now - host["last_seen"]
                host["iat_list"].append(iat)

            host["last_seen"] = now
            host["total_packets"] += 1
            host["total_bytes"] += packet_info["packet_size"]
            host["packet_times"].append(now)

            # TCP flags
            flags = packet_info.get("tcp_flags", "")
            if "S" in flags:
                host["syn_count"] += 1
            if "A" in flags:
                host["ack_count"] += 1
            if "R" in flags:
                host["rst_count"] += 1
            if "P" in flags:
                host["psh_count"] += 1

            # Remove old packets outside window
            host["packet_times"] = [
                t for t in host["packet_times"]
                if now - t <= self.window_size
            ]

            # Trigger ML if enough activity
            if len(host["packet_times"]) > 20:
                return self._extract_features(host)

        return None
    
    def _extract_features(self, host):

        duration = max(host["last_seen"] - host["start_time"], 1e-6)

        packets_per_sec = host["total_packets"] / duration
        bytes_per_sec = host["total_bytes"] / duration

        iat_array = np.array(host["iat_list"]) if host["iat_list"] else np.array([0])

        return {
            "Flow Duration": duration * 1_000_000,
            "Total Packets": host["total_packets"],
            "Total Bytes": host["total_bytes"],
            "Packet Length Mean": 0,
            "Packet_Size_Var": 0,
            "Packets_per_sec": packets_per_sec,
            "Bytes_per_sec": bytes_per_sec,
            "Total Fwd Packets": host["total_packets"],
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": host["total_bytes"],
            "Total Length of Bwd Packets": 0,
            "SYN Flag Count": host["syn_count"],
            "RST Flag Count": host["rst_count"],
            "ACK Flag Count": host["ack_count"],
            "PSH Flag Count": host["psh_count"],
            "Flow IAT Mean": float(np.mean(iat_array)),
            "Flow IAT Std": float(np.std(iat_array)),
        }

    def reset(self):
        with self.lock:
            self.host_table.clear()