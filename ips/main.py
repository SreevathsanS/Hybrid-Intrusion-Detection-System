import json
import signal
import sys
import subprocess
import os
import atexit
import time
import threading

from flow_manager import FlowManager
from behavior_engine import BehaviorEngine
from volumetric_engine import VolumetricEngine
from ml_engine import MLEngine
from expiry_engine import ExpiryEngine
from block_manager import BlockManager
from nfqueue_handler import InlineIPS
from host_aggregator import HostAggregator
from config import FLOW_TIMEOUT, SCAN_INTERVAL, MODEL_PATH, ENCODER_PATH
from attack_session_manager import AttackSessionManager
from attack_logger import AttackLogger
from web3 import Web3

VENV_PYTHON = "/home/vathsan/ids_env/bin/python3"

# =====================================
# GLOBAL EXPORTS FOR DASHBOARD
# =====================================
GLOBAL_BLOCK_MANAGER = None
GLOBAL_SESSION_MANAGER = None
GLOBAL_VOLUMETRIC_ENGINE = None
GLOBAL_BEHAVIOR_ENGINE = None

QUEUE_NUM = 0
iptables_rules_added = False

# =====================================
# STATUS FILE SETUP
# =====================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

STATUS_FILE = "/mnt/hgfs/IDS-hybrid-shared/ips/logs/system_status.json"


def status_writer():
    """
    Continuously writes IPS system state to JSON file
    so dashboard can read it.
    """
    while True:
        try:
            if GLOBAL_BLOCK_MANAGER is not None:
                status_data = {
                    "system_state": GLOBAL_BLOCK_MANAGER.system_state,
                    "blocked_ips": list(GLOBAL_BLOCK_MANAGER.blocked_ips.keys()),
                    "active_blocks": GLOBAL_BLOCK_MANAGER.blocked_ips
                }

                with open(STATUS_FILE, "w") as f:
                    json.dump(status_data, f)

        except Exception as e:
            print("[STATUS WRITER ERROR]", e)

        time.sleep(2)
#----------------------------------------------------------
# BLOCKCHAIN STATUS
#----------------------------------------------------------

BLOCKCHAIN_STATUS_FILE = "/mnt/hgfs/IDS-hybrid-shared/ips/logs/blockchain_status.json"
def blockchain_status_writer():
    while True:
        try:
            w3 = Web3(Web3.HTTPProvider("http://192.168.111.1:7545"))

            status_data = {
                "connected": w3.is_connected(),
                "block_number": w3.eth.block_number if w3.is_connected() else None
            }

            with open(BLOCKCHAIN_STATUS_FILE, "w") as f:
                json.dump(status_data, f)

        except Exception as e:
            with open(BLOCKCHAIN_STATUS_FILE, "w") as f:
                json.dump({
                    "connected": False,
                    "block_number": None
                }, f)

        time.sleep(3)

        
LIVE_ATTACK_FILE = "/mnt/hgfs/IDS-hybrid-shared/ips/logs/live_attacks.json"
def live_attack_writer():
    while True:
        try:
            active_sessions = []

            if GLOBAL_SESSION_MANAGER:
                for ip, session in GLOBAL_SESSION_MANAGER.active_sessions.items():
                    active_sessions.append({
                        "src_ip": ip,
                        "attack_type": session.attack_type,
                        "start_time": session.start_time,
                        "packet_count": session.packet_count,
                        "status": "ACTIVE"
                    })

            with open(LIVE_ATTACK_FILE, "w") as f:
                json.dump(active_sessions, f)

        except Exception as e:
            print("[LIVE ATTACK WRITER ERROR]", e)

        time.sleep(1)
# ---------------------------------------------------------
# IPTABLES MANAGEMENT
# ---------------------------------------------------------
def setup_iptables():
    global iptables_rules_added

    print("[+] Setting up iptables rules...")

    check_rule = subprocess.run(
        ["iptables", "-C", "INPUT", "-p", "tcp",
         "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if check_rule.returncode == 0:
        print("[!] NFQUEUE rule already exists.")
        return

    subprocess.run(
        ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]
    )

    subprocess.run(
        ["iptables", "-I", "INPUT", "-i", "lo", "-j", "ACCEPT"]
    )

    subprocess.run(
        ["iptables", "-I", "INPUT", "-p", "tcp",
         "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)]
    )

    iptables_rules_added = True


def remove_nfqueue_rule():
    global iptables_rules_added

    if not iptables_rules_added:
        return

    print("[+] Removing NFQUEUE rule...")

    subprocess.run(
        ["iptables", "-D", "INPUT", "-p", "tcp",
         "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


# ---------------------------------------------------------
# CLEAN SHUTDOWN
# ---------------------------------------------------------
def shutdown_handler(signum=None, frame=None):
    print("\n[!] Shutting down IPS safely...")

    try:
        ips.stop()
    except Exception:
        pass

    try:
        expiry_engine.stop()
    except Exception:
        pass

    remove_nfqueue_rule()
    sys.exit(0)


atexit.register(remove_nfqueue_rule)


# ---------------------------------------------------------
# MAIN ENTRY
# ---------------------------------------------------------
if __name__ == "__main__":

    print("======================================")
    print("        HYBRID INLINE ML IPS")
    print("======================================")

    # -----------------------------------------------------
    # Deploy Smart Contract
    # -----------------------------------------------------
    print("[1] Deploying Smart Contract...")

    PROJECT_ROOT = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )

    deploy_script = os.path.join(
        PROJECT_ROOT,
        "blockchain_module",
        "scripts",
        "deploy_contract.py"
    )

    deploy_output = subprocess.check_output(
        [VENV_PYTHON, deploy_script],
        text=True
    )

    print(deploy_output)

    deployed_account = None
    contract_address = None

    for line in deploy_output.splitlines():
        if line.startswith("DEPLOYED_ACCOUNT="):
            deployed_account = line.split("=")[1].strip()
        if line.startswith("CONTRACT_ADDRESS="):
            contract_address = line.split("=")[1].strip()

    if not deployed_account or not contract_address:
        raise RuntimeError("Blockchain deployment failed")

    os.environ["DEPLOYED_ACCOUNT"] = deployed_account
    os.environ["CONTRACT_ADDRESS"] = contract_address

    print(f"[✓] Blockchain Ready")
    print(f"Account: {deployed_account}")
    print(f"Contract: {contract_address}")

    # -----------------------------------------------------
    # Initialize Components
    # -----------------------------------------------------
    flow_manager = FlowManager(
        packet_threshold=5,
        flow_timeout=FLOW_TIMEOUT
    )

    behavior_engine = BehaviorEngine()

    volumetric_engine = VolumetricEngine(
        window_size=5,
        pps_threshold=20000,
        bps_threshold=5_000_000,
        syn_threshold=50,
        forward_threshold=500
    )

    attack_logger = AttackLogger(
        log_file=os.path.join(LOG_DIR, "attack_summary_log.jsonl"),
    )

    attack_session_manager = AttackSessionManager(
        attack_logger=attack_logger,
        session_timeout=10
    )

    block_manager = BlockManager(
        block_duration=5,
        attack_session_manager=attack_session_manager,
        behavior_engine=behavior_engine,
        volumetric_engine=volumetric_engine,
        flow_manager=flow_manager
    )

    ml_engine = MLEngine(
        MODEL_PATH,
        ENCODER_PATH,
        confidence_threshold=0.85
    )

    host_aggregator = HostAggregator(window_size=10)

    expiry_engine = ExpiryEngine(
        flow_manager,
        behavior_engine,
        volumetric_engine,
        block_manager,
        attack_session_manager=attack_session_manager,
        interval=SCAN_INTERVAL
    )

    ips = InlineIPS(
        flow_manager,
        behavior_engine,
        volumetric_engine,
        ml_engine,
        block_manager,
        expiry_engine,
        host_aggregator,
        queue_num=QUEUE_NUM
    )

    # =====================================
    # EXPORT OBJECTS FOR DASHBOARD
    # =====================================
    GLOBAL_BLOCK_MANAGER = block_manager
    GLOBAL_SESSION_MANAGER = attack_session_manager
    GLOBAL_VOLUMETRIC_ENGINE = volumetric_engine
    GLOBAL_BEHAVIOR_ENGINE = behavior_engine

    # Clear residual state
    flow_manager.flow_table.clear()
    volumetric_engine.source_stats.clear()
    behavior_engine.source_activity.clear()
    host_aggregator.reset()

    # Register Signals
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Start IPS
    setup_iptables()
    expiry_engine.start()

    # Start Status Writer Thread
    status_thread = threading.Thread(target=status_writer, daemon=True)
    status_thread.start()

    blockchain_thread = threading.Thread(
        target=blockchain_status_writer,
        daemon=True
    )
    blockchain_thread.start()
    live_thread = threading.Thread(target=live_attack_writer, daemon=True)
    live_thread.start()
    
    print("[+] IPS running inline...")
    print("[+] Press Ctrl+C to stop.\n")

    try:
        ips.start()
    except Exception as e:
        print("[CRITICAL] IPS crashed:", e)
        shutdown_handler()