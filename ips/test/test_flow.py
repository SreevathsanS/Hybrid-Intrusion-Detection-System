# test_flow.py

import time
from flow_manager import FlowManager

flow_manager = FlowManager(flow_timeout=5)

# Simulate packets
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

print("Active flows:", flow_manager.get_flow_count())

print("Waiting for expiration...")
time.sleep(6)

expired = flow_manager.expire_flows()

print("Expired flows:", len(expired))
print("Active flows after cleanup:", flow_manager.get_flow_count())
