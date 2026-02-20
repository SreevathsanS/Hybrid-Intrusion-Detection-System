import time
import threading


class VolumetricEngine:
    def __init__(
        self,
        window_size=3,                 # seconds
        pps_threshold=5000,            # packets per second
        bps_threshold=5_000_000,       # bytes per second (5 MB/s)
        syn_threshold=200,             # SYN packets in window
        forward_threshold=500,         # forward-only packets
        debug=False
    ):
        self.window_size = window_size
        self.pps_threshold = pps_threshold
        self.bps_threshold = bps_threshold
        self.syn_threshold = syn_threshold
        self.forward_threshold = forward_threshold
        self.debug = debug

        self.source_stats = {}
        self.lock = threading.RLock()

    # ---------------------------------------------------------
    # Main Detection Function
    # ---------------------------------------------------------
    def check(self, packet_info):

        src_ip = packet_info["src_ip"]
        now = packet_info["timestamp"]

        with self.lock:

            if src_ip not in self.source_stats:
                self.source_stats[src_ip] = []

            # Store packet data
            self.source_stats[src_ip].append(
                (
                    now,
                    packet_info["packet_size"],
                    packet_info.get("tcp_flags", ""),
                    packet_info.get("is_forward", True)
                )
            )

            self._prune(src_ip, now)

            entries = self.source_stats[src_ip]
            if not entries:
                return False, None

            packet_count = len(entries)
            total_bytes = sum(e[1] for e in entries)

            syn_count = sum(1 for e in entries if "S" in e[2])
            ack_count = sum(1 for e in entries if "A" in e[2])

            forward_packets = sum(1 for e in entries if e[3])
            backward_packets = packet_count - forward_packets

            duration = max(now - entries[0][0], 1e-6)

            pps = packet_count / duration
            bps = total_bytes / duration

            if self.debug:
                print(
                    f"[VOL DEBUG] IP={src_ip} | "
                    f"PPS={pps:.2f} | BPS={bps:.2f} | "
                    f"SYN={syn_count} | ACK={ack_count} | "
                    f"FWD={forward_packets} | BWD={backward_packets}"
                )

            # =====================================================
            # 1️⃣ SYN Flood (check BEFORE PPS)
            # =====================================================
            if (
                syn_count >= self.syn_threshold
                and ack_count < (syn_count * 0.2)
            ):
                return True, "SYN_FLOOD"

            # =====================================================
            # 2️⃣ High PPS
            # =====================================================
            if pps >= self.pps_threshold:
                # Only skip if it's a LOW-rate SYN scan (port scan behaviour)
                # A real SYN flood will already be caught above by syn_threshold
                # So if we're here with high PPS, it's a flood regardless
                return True, "DDoS_PPS"

            # =====================================================
            # 3️⃣ High BPS
            # =====================================================
            if bps >= self.bps_threshold:
                return True, "DDoS_BPS"

            # =====================================================
            # 4️⃣ Forward-only Flood
            # =====================================================
            if (
                forward_packets >= self.forward_threshold
                and backward_packets == 0
            ):
                return True, "FORWARD_ONLY_FLOOD"

        return False, None

    # ---------------------------------------------------------
    def _prune(self, src_ip, now):
        cutoff = now - self.window_size
        self.source_stats[src_ip] = [
            entry for entry in self.source_stats[src_ip]
            if entry[0] >= cutoff
        ]

    # ---------------------------------------------------------
    def expire_sources(self):
        now = time.time()
        cutoff = now - self.window_size

        with self.lock:
            expired_ips = []

            for ip, entries in self.source_stats.items():
                if not entries:
                    expired_ips.append(ip)
                    continue

                if max(e[0] for e in entries) < cutoff:
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self.source_stats[ip]
