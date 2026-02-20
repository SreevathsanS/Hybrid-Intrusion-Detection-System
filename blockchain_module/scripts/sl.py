# --------------------------------------------------
# store_log.py
# Stores ML-based IDS logs on Blockchain
# --------------------------------------------------

import sys
import time
import json
import hashlib
import pandas as pd
from web3 import Web3
import os
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# --------------------------------------------------
# ADD PROJECT ROOT TO PATH (for ML imports)
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR,"..",".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# --------------------------------------------------
# IMPORT ML 
# --------------------------------------------------
from blockchain_module.config.attack_config import ATTACK_SCENARIO,ATTACKER_IP,VICTIM_IP
from ML.predict import predict_intrusion


# --------------------------------------------------
# CONNECT TO GANACHE
# --------------------------------------------------
GANACHE_URL = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

assert web3.is_connected(), "Ganache is not connected"

# --------------------------------------------------
# LOAD ACCOUNT
# --------------------------------------------------

account = os.getenv("DEPLOYED_ACCOUNT")
if not account:
    account= web3.eth.accounts[0]

print(" Connected to Ganache")
print(" Using account", account)

# --------------------------------------------------
# LOAD CONTRACT ABI
# --------------------------------------------------
ABI_PATH = os.path.join(
    BASE_DIR,
    "..",
    "abi",
    "IDSLogStorage.json"
)
ABI_PATH = os.path.abspath(ABI_PATH)
with open(ABI_PATH, "r") as abi_file:
    abi = json.load(abi_file)

# --------------------------------------------------
# LOAD CONTRACT ADDRESS
# --------------------------------------------------
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
CONTRACT_ADDRESS = Web3.to_checksum_address(CONTRACT_ADDRESS)

contract = web3.eth.contract(
    address=CONTRACT_ADDRESS,
    abi=abi
)

print(" Smart Contract Loaded")

# --------------------------------------------------
# LOAD FEATURE CSV BASED ON ATTACK SCENARIO
# --------------------------------------------------

DATA_DIR = os.path.join(PROJECT_ROOT,"data")


if ATTACK_SCENARIO == "BRUTEFORCE":
    feature_path = os.path.join(DATA_DIR,"bruteforce_features.csv")
    protocol = "TCP"
    service = "SSH"
    attack_label = "BruteForce"

elif ATTACK_SCENARIO == "DOS":
    feature_path = os.path.join(DATA_DIR,"dos_feature_extractor.csv")
    protocol = "TCP"  # SYN flood
    service ="HTTP"         
    attack_label = "DoS"

else:
    raise ValueError("Invalid ATTACK_SCENARIO")

df = pd.read_csv(feature_path)

#--------------------------------------------------
# ML PREDICTION
#--------------------------------------------------

prediction, attack_type = predict_intrusion(df)
print(" ML Prediction:", prediction)
print(" Attack Type:", attack_type)

# --------------------------------------------------
# BUILD IDS LOG
# --------------------------------------------------
ids_log = {
    "timestamp": int(time.time()),
    "src_ip": ATTACKER_IP,
    "dst_ip": VICTIM_IP,
    "protocol": protocol,
    "service" : service,
    "prediction": prediction,
    "attack_type": attack_type
}

print(" IDS Log:", ids_log)

# --------------------------------------------------
# HASH IDS LOG (SHA-256)
# --------------------------------------------------
log_string = json.dumps(ids_log, sort_keys=True)
log_hash = hashlib.sha256(log_string.encode()).hexdigest()

print(" Log Hash:", log_hash)

# --------------------------------------------------
# STORE LOG ON BLOCKCHAIN
# --------------------------------------------------
tx_hash = contract.functions.storeLog(
    ids_log["src_ip"],
    ids_log["dst_ip"],
    ids_log["protocol"],
    ids_log["prediction"],
    ids_log["attack_type"],
    log_hash
).transact({
    "from": account
})

# Wait for confirmation
receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

print(" IDS Log Successfully Stored on Blockchain")
print(" Block Number:", receipt.blockNumber)
print(" Transaction Hash:", receipt.transactionHash.hex())
