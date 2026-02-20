# realtime_store_log.py
import json
import hashlib
import time
import os
from web3 import Web3

LAST_WRITE = {}
BLOCKCHAIN_COOLDOWN =10  # seconds per IP per attack

# ------------------------------
# CONNECT TO GANACHE
# ------------------------------
GANACHE_URL = "http://192.168.111.1:7545"
web3 = Web3(Web3.HTTPProvider(GANACHE_URL,request_kwargs={'timeout': 60}))
assert web3.is_connected(), "Ganache not connected"

# ------------------------------
# LOAD ACCOUNT
# ------------------------------
account = os.getenv("DEPLOYED_ACCOUNT", web3.eth.accounts[0])

# ------------------------------
# LOAD ABI
# ------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ABI_PATH = os.path.join(BASE_DIR, "..", "abi", "IDSLogStorage.json")

with open(ABI_PATH, "r") as f:
    abi = json.load(f)

# ------------------------------
# LOAD CONTRACT
# ------------------------------
contract_address = os.getenv("CONTRACT_ADDRESS")

if not contract_address:
    raise RuntimeError("CONTRACT_ADDRESS not set in environment")

contract_address = Web3.to_checksum_address(contract_address)

contract = web3.eth.contract(
    address=contract_address,
    abi=abi
)

# ------------------------------
# MAIN FUNCTION (THIS IS KEY)
# ------------------------------
def store_realtime_log(event: dict):
    """
    event = {
        timestamp, src_ip, dst_ip,
        protocol, attack_type, confidence
    }
    """

    key = f"{event['src_ip']}_{event['attack_type']}"
    now = time.time()

    #-------------------------------------
    # RATE LIMITING (CROTICAL FIX)
    #-------------------------------------
    if key in LAST_WRITE:
        if now - LAST_WRITE[key] < BLOCKCHAIN_COOLDOWN:
            return # Skip writing to blockchain

    LAST_WRITE[key] = now

    ids_log = {
        "timestamp": event["timestamp"],
        "src_ip": event["src_ip"],
        "dst_ip": "N/A",
        "protocol": "TCP",
        "prediction": "Attack",
        "attack_type": event["attack_type"]
    }

    log_string = json.dumps(ids_log, sort_keys=True)
    log_hash = hashlib.sha256(log_string.encode()).hexdigest()

    try:
        tx_hash = contract.functions.storeLog(
            ids_log["src_ip"],
            ids_log["dst_ip"],
            ids_log["protocol"],
            ids_log["prediction"],
            ids_log["attack_type"],
            log_hash
        ).transact({
            "from": account,
            "gas": 3000000
        })

        #web3.eth.wait_for_transaction_receipt(tx_hash)
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        # NON-BLOCKING: do NOT wait for receipt
        print(f"[BLOCKCHAIN] Stored {ids_log['attack_type']} from {ids_log['src_ip']}")
        return web3.to_hex(tx_hash)

    except Exception as e:
        print(f"[BLOCKCHAIN ERROR] {e}")