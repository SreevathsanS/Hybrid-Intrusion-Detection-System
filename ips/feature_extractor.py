# feature_extractor.py
import numpy as np

FEATURE_NAMES = [
    "duration",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "packet_size_var",
    "packets_per_sec",
    "bytes_per_sec",
    "fwd_packet_count",
    "bwd_packet_count",
    "fwd_byte_count",
    "bwd_byte_count",
    "syn_count",
    "rst_count",
    "ack_count",
    "psh_count",
    "fin_count",
    "flow_iat_mean",
    "flow_iat_std"
]

def extract_features(flow):
    """
    Accepts a Flow object (from flow_manager.Flow) and returns a list of features
    in the same order as FEATURE_NAMES.
    """
    duration = max(flow.duration(), 1e-9)  # avoid div by zero
    total_packets = float(flow.packet_count)
    total_bytes = float(flow.byte_count)

    if flow.packet_sizes:
        avg_packet_size = float(np.mean(flow.packet_sizes))
        packet_size_var = float(np.var(flow.packet_sizes))
    else:
        avg_packet_size = 0.0
        packet_size_var = 0.0

    packets_per_sec = total_packets / duration
    bytes_per_sec = total_bytes / duration

    fwd_packet_count = float(getattr(flow, "fwd_packet_count", 0))
    bwd_packet_count = float(getattr(flow, "bwd_packet_count", 0))
    fwd_byte_count = float(getattr(flow, "fwd_byte_count", 0))
    bwd_byte_count = float(getattr(flow, "bwd_byte_count", 0))

    syn_count = float(getattr(flow, "syn_count", 0))
    rst_count = float(getattr(flow, "rst_count", 0))
    ack_count = float(getattr(flow, "ack_count", 0))
    psh_count = float(getattr(flow, "psh_count", 0))
    fin_count = float(getattr(flow, "fin_count", 0))

    if flow.iat_list:
        # ignore first iat=0 maybe — we include it but mean/std will reflect distribution
        flow_iat_mean = float(np.mean(flow.iat_list))
        flow_iat_std = float(np.std(flow.iat_list))
    else:
        flow_iat_mean = 0.0
        flow_iat_std = 0.0

    features = [
        duration,
        total_packets,
        total_bytes,
        avg_packet_size,
        packet_size_var,
        packets_per_sec,
        bytes_per_sec,
        fwd_packet_count,
        bwd_packet_count,
        fwd_byte_count,
        bwd_byte_count,
        syn_count,
        rst_count,
        ack_count,
        psh_count,
        flow_iat_mean,
        flow_iat_std
    ]

    return features
