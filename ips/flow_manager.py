import time
import threading
import numpy as np


class FlowManager:
    def __init__(self, packet_threshold=10, flow_timeout=20, ml_engine=None):
        self.flow_table = {}
        self.lock = threading.RLock()

        self.packet_threshold = packet_threshold
        self.flow_timeout = flow_timeout

        # NEW: Needed for post-expiry classification
        self.ml_engine = ml_engine

    # ---------------------------------------------------------
    # Canonical bidirectional flow key
    # ---------------------------------------------------------
    def _get_flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)

    # ---------------------------------------------------------
    # Public method to access flow (used by IPS)
    # ---------------------------------------------------------
    def get_flow(self, key):
        with self.lock:
            return self.flow_table.get(key)

    # ---------------------------------------------------------
    # Update flow with packet
    # ---------------------------------------------------------
    def update_flow(self, packet_info):

        key = self._get_flow_key(
            packet_info["src_ip"],
            packet_info["dst_ip"],
            packet_info["src_port"],
            packet_info["dst_port"],
            packet_info["protocol"]
        )

        with self.lock:
            now = packet_info["timestamp"]

            if key not in self.flow_table:
                self.flow_table[key] = self._create_new_flow(now)

            flow = self.flow_table[key]

            # Direction check
            is_forward = (
                packet_info["src_ip"],
                packet_info["src_port"]
            ) == (key[0], key[2])

            # IAT
            if flow["last_seen"] is not None:
                iat = (now - flow["last_seen"]) * 1_000_000
                flow["iat_list"].append(iat)
                if len(flow["iat_list"]) > 200:
                    flow["iat_list"].pop(0)

            flow["last_seen"] = now

            # Packet stats
            flow["total_packets"] += 1
            flow["total_bytes"] += packet_info["packet_size"]

            flow["packet_lengths"].append(packet_info["packet_size"])
            if len(flow["packet_lengths"]) > 200:
                flow["packet_lengths"].pop(0)

            # Directional stats
            if is_forward:
                flow["fwd_packets"] += 1
                flow["fwd_bytes"] += packet_info["packet_size"]
            else:
                flow["bwd_packets"] += 1
                flow["bwd_bytes"] += packet_info["packet_size"]

            # TCP flags
            flags = packet_info.get("tcp_flags", "")
            if "S" in flags:
                flow["syn_count"] += 1
            if "A" in flags:
                flow["ack_count"] += 1
            if "R" in flags:
                flow["rst_count"] += 1
            if "P" in flags:
                flow["psh_count"] += 1

            # -------------------------
            # REAL-TIME ML TRIGGER
            # -------------------------
            if (
                flow["total_packets"] >= self.packet_threshold
                and not flow["ml_checked"]
            ):
                flow["ml_checked"] = True

                print("ML TRIGGERED FOR FLOW:", key)

                features = self._extract_features(flow)
                return key, features

        return None, None

    # ---------------------------------------------------------
    # Create new flow
    # ---------------------------------------------------------
    def _create_new_flow(self, timestamp):
        return {
            "start_time": timestamp,
            "last_seen": timestamp,
            "total_packets": 0,
            "total_bytes": 0,

            "fwd_packets": 0,
            "bwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,

            "packet_lengths": [],
            "iat_list": [],

            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
            "psh_count": 0,

            "ml_checked": False,

            # NEW FIELDS (For Post-Flow Classification)
            "blocked": False,
            "trigger_reason": None
        }

    # ---------------------------------------------------------
    # Feature Extraction (Aligned with Model)
    # ---------------------------------------------------------
    def _extract_features(self, flow):

        duration_seconds = max(flow["last_seen"] - flow["start_time"], 1e-6)
        duration_microseconds = duration_seconds * 1_000_000

        packets_per_sec = flow["total_packets"] / duration_seconds
        bytes_per_sec = flow["total_bytes"] / duration_seconds

        packet_lengths = np.array(flow["packet_lengths"])
        iat_array = np.array(flow["iat_list"]) if flow["iat_list"] else np.array([0])

        features = {
            "Flow Duration": duration_microseconds,
            "Total Packets": flow["total_packets"],
            "Total Bytes": flow["total_bytes"],
            "Packet Length Mean": float(np.mean(packet_lengths)),
            "Packet_Size_Var": float(np.var(packet_lengths)),
            "Packets_per_sec": packets_per_sec,
            "Bytes_per_sec": bytes_per_sec,
            "Total Fwd Packets": flow["fwd_packets"],
            "Total Backward Packets": flow["bwd_packets"],
            "Total Length of Fwd Packets": flow["fwd_bytes"],
            "Total Length of Bwd Packets": flow["bwd_bytes"],
            "SYN Flag Count": flow["syn_count"],
            "RST Flag Count": flow["rst_count"],
            "ACK Flag Count": flow["ack_count"],
            "PSH Flag Count": flow["psh_count"],
            "Flow IAT Mean": float(np.mean(iat_array)),
            "Flow IAT Std": float(np.std(iat_array)),
        }

        return features

    # ---------------------------------------------------------
    # Expire Old Flows (POST-FLOW ML HERE)
    # ---------------------------------------------------------
    def expire_flows(self):

        now = time.time()

        with self.lock:

            expired_keys = [
                key for key, flow in self.flow_table.items()
                if now - flow["last_seen"] > self.flow_timeout
            ]

            for key in expired_keys:

                flow = self.flow_table[key]

                # -----------------------------
                # POST-FLOW CLASSIFICATION
                # -----------------------------
                if flow.get("blocked") and self.ml_engine is not None:

                    print(f"\n[POST-FLOW ML] Classifying expired flow: {key}")

                    features = self._extract_features(flow)

                    try:
                        is_attack, label, confidence = self.ml_engine.predict(features)

                        print(f"[FINAL CLASSIFICATION] {label} | {confidence:.4f}")

                    except Exception as e:
                        print("Post-flow ML error:", e)

                # Remove flow
                del self.flow_table[key]
