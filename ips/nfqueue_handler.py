import time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP

WHITELIST_PORTS = {7545}  # Ganache host
class InlineIPS:

    def __init__(
        self,
        flow_manager,
        behavior_engine,
        volumetric_engine,
        ml_engine,
        block_manager,
        expiry_engine,
        host_aggregator,
        queue_num=0
    ):
        # Add at the top of InlineIPS.__init__()
        
        self.flow_manager = flow_manager
        self.behavior_engine = behavior_engine
        self.volumetric_engine = volumetric_engine
        self.ml_engine = ml_engine
        self.block_manager = block_manager
        self.expiry_engine = expiry_engine
        self.host_aggregator = host_aggregator
        self.queue_num = queue_num
        self.startup_time = time.time()
        self.warmup_period = 5

        self.nfqueue = NetfilterQueue()
        self.running = False

    # ---------------------------------------------------------
    # Start IPS
    # ---------------------------------------------------------
    def start(self):
        print("[INLINE IPS] Binding NFQUEUE...")
        self.running = True
        self.nfqueue.bind(self.queue_num, self.process_packet)
        self.nfqueue.run()

    # ---------------------------------------------------------
    # Stop IPS
    # ---------------------------------------------------------
    def stop(self):
        self.running = False
        try:
            self.nfqueue.unbind()
        except Exception:
            pass

    # ---------------------------------------------------------
    # Packet Processor
    # ---------------------------------------------------------
    def process_packet(self, packet):

        try:
            if time.time() - self.startup_time < self.warmup_period:
                packet.accept()
                return

            payload = packet.get_payload()

            if len(payload) < 20:
                packet.accept()
                return

            ip = IP(payload)

            src_ip = ip.src
    
            dst_ip = ip.dst
            protocol = ip.proto
            packet_size = len(payload)
            timestamp = time.time()

            # -------------------------------------------------
            # Drop immediately if source already blocked
            # -------------------------------------------------
            if self.block_manager.is_blocked(src_ip):
                packet.drop()
                return

            src_port = 0
            dst_port = 0
            tcp_flags = ""

            if ip.haslayer(TCP):
                tcp = ip[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = str(tcp.flags)

            elif ip.haslayer(UDP):
                udp = ip[UDP]
                src_port = udp.sport
                dst_port = udp.dport

            # Whitelist check — never block trusted IPs (Ganache, etc.)
            if dst_port in WHITELIST_PORTS or src_port in WHITELIST_PORTS:
                packet.accept()
                return
    
            # =================================================
            # 1️⃣ BEHAVIOR ENGINE
            # =================================================
            behavior_attack, behavior_type = self.behavior_engine.check({
                "src_ip": src_ip,
                "dst_port": dst_port,
                "timestamp": timestamp
            })

            if behavior_attack:
                self.block_manager.block_ip(src_ip, behavior_type, 1.0)
                packet.drop()
                return

            # =================================================
            # 2️⃣ VOLUMETRIC ENGINE
            # =================================================
            SKIP_VOLUMETRIC_SRC_PORTS = {80, 443, 53}  # HTTP, HTTPS, DNS responses
            if src_port not in SKIP_VOLUMETRIC_SRC_PORTS:

                volumetric_attack, volumetric_type = self.volumetric_engine.check({
                    "src_ip": src_ip,
                    "packet_size": packet_size,
                    "tcp_flags": tcp_flags,
                    "timestamp": timestamp
                })

                if volumetric_attack:
                    self.block_manager.block_ip(src_ip, volumetric_type, 1.0)
                    packet.drop()
                    return

            # =================================================
            # 3️⃣ HOST-LEVEL ML (Aggregated)
            # =================================================
            host_features = self.host_aggregator.update({
                "src_ip": src_ip,
                "packet_size": packet_size,
                "tcp_flags": tcp_flags,
                "timestamp": timestamp
            })

            if host_features:
                is_attack, label, confidence = self.ml_engine.predict(host_features)

                if is_attack:
                    self.block_manager.block_ip(src_ip, label, confidence)
                    packet.drop()
                    return

            # =================================================
            # 4️⃣ FLOW-LEVEL ML
            # =================================================
            key, features = self.flow_manager.update_flow({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_size": packet_size,
                "tcp_flags": tcp_flags,
                "timestamp": timestamp
            })

            if features is not None:
                is_attack, label, confidence = self.ml_engine.predict(features)

                if is_attack:
                    self.block_manager.block_ip(src_ip, label, confidence)
                    packet.drop()
                    return

            # -------------------------------------------------
            # Accept packet if no detection
            # -------------------------------------------------
            packet.accept()

        except Exception:
            # Never allow packet processing to crash IPS
            packet.accept()
