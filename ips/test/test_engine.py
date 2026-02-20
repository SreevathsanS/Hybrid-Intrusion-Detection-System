# test_engine.py

import time
from flow_manager import FlowManager
from expiry_engine import ExpiryEngine
from ml_engine import MLEngine
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
flow_manager = FlowManager(flow_timeout=5)
ml_engine = MLEngine("cicids2017_ips_network_only.json")
engine = ExpiryEngine(flow_manager,ml_engine)

engine.start()

# Simulate traffic
for i in range(5):
    flow_manager.add_or_update_flow(
        "192.168.1.10",
        "192.168.1.20",
        1234,
        80,
        "TCP",
        500
    )
    time.sleep(1)

print("Traffic sent. Waiting for auto-expiry...")

time.sleep(10)

engine.stop()
print("Engine stopped.")
