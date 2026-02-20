import json
import hashlib
import os
import time
from web3 import Web3


class BlockchainLogger:

    def __init__(self):

        # --------------------------------------------------
        # CONNECT TO GANACHE
        # --------------------------------------------------
        GANACHE_URL = "http://127.0.0.1:7545"
        self.web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

        if not self.web3.is_connected():
            raise Exception("Ganache not connected")

        # --------------------------------------------------
        # LOAD ACCOUNT
        # --------------------------------------------------
        self.account = os.getenv("DEPLOYED_ACCOUNT")
        if not self.account:
            self.account = self.web3.eth.accounts[0]

        # --------------------------------------------------
        # LOAD ABI
        # --------------------------------------------------
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        ABI_PATH = os.path.join(
            BASE_DIR,
            "..",
            "blockchain_module",
            "abi",
            "IDSLogStorage.json"
        )
        ABI_PATH = os.path.abspath(ABI_PATH)

        with open(ABI_PATH, "r") as abi_file:
            abi = json.load(abi_file)

        # --------------------------------------------------
        # LOAD CONTRACT ADDRESS
        # --------------------------------------------------
        contract_address = os.getenv("CONTRACT_ADDRESS")

        if not contract_address:
            raise Exception("CONTRACT_ADDRESS not set in environment")

        contract_address = Web3.to_checksum_address(contract_address)

        self.contract = self.web3.eth.contract(
            address=contract_address,
            abi=abi
        )

        print("Blockchain Logger Initialized")

    # --------------------------------------------------
    # Log attack session to blockchain
    # --------------------------------------------------
    def log_attack(self, session):

        ids_log = {
            "timestamp": int(time.time()),
            "src_ip": session["ip"],
            "dst_ip": "PROTECTED_HOST",
            "protocol": "TCP",
            "prediction": "ATTACK",
            "attack_type": session["attack_type"]
        }

        log_string = json.dumps(ids_log, sort_keys=True)
        log_hash = hashlib.sha256(log_string.encode()).hexdigest()

        tx_hash = self.contract.functions.storeLog(
            ids_log["src_ip"],
            ids_log["dst_ip"],
            ids_log["protocol"],
            ids_log["prediction"],
            ids_log["attack_type"],
            log_hash
        ).transact({
            "from": self.account
        })

        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        print("BLOCKCHAIN STORED → Block:", receipt.blockNumber)
