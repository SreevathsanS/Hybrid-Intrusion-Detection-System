import subprocess
import sys
import os
import argparse

VENV_PYTHON = "/home/vathsan/ids_env/bin/python3"

parser = argparse.ArgumentParser()
parser.add_argument(
    "--mode",
    choices=["offline","realtime"],
    default="offline",
    help="Run IDS in Offline or Realtime mode"
)
args = parser.parse_args()

print("\n================================================")
print(" IDS HYBRID SYSTEM STARTING")
print(" Mode:",args.mode.upper())
print("\n================================================")

#------------------------------------------
# STEP 1 DEPLOY THE SMART CONTRACT
#------------------------------------------

print("[1] DEPLOYING SMART CONTRACT...........")

deploy_process = subprocess.check_output(
    [VENV_PYTHON,"blockchain_module/scripts/deploy_contract.py"],
    text=True

)
print(deploy_process)

#------------------------------------------
# PARSE DEPLOY OUTPUT
#------------------------------------------

deploy_account = None
contract_account = None

for line in deploy_process.splitlines():
    if line.startswith("DEPLOYED_ACCOUNT="):
        deploy_account = line.split("=")[1].strip()
    if line.startswith("CONTRACT_ADDRESS="):
        contract_account = line.split("=")[1].strip()

if not deploy_account or not contract_account:
    raise RuntimeError("Failed to reterive the blockchain deploymentb details")

print(f"Account: {deploy_account}")
print(f"Contract: {contract_account}")

os.environ["DEPLOYED_ACCOUNT"] = deploy_account
os.environ["CONTRACT_ADDRESS"] = contract_account

#------------------------------------------
# Offline Mode Pipeline
#------------------------------------------
if args.mode == "offline":
    from blockchain_module.config.attack_config import ATTACK_SCENARIO
    
    print("[2] Extracting Features")
    subprocess.run(
        [VENV_PYTHON,"ML/offline_feature_extraction.py",
         "--pcap",f"data/pcaps/{ATTACK_SCENARIO['pcap_file']}",
         "--output","data/offline_features.csv"],
        check=True
    )
    print("\n[3] Running OFFLINE ML Prediction + Blockchain Logging...")
    
#------------------------------------------
# Realtime Mode Pipeline
#------------------------------------------

elif args.mode == "realtime":
    print("[2] Starting Realtime IDS Sniffer + ML + Blockchain Logging...")

    subprocess.run(
        [
            "sudo",
            "-E",
            "PYTHONPATH=/mnt/hgfs/IDS-hybrid-shared",
            VENV_PYTHON,
            "realtime_ids/realtime_runner.py"
        ],
        check=True
    )
print("\n================================================")
print("IDS PIPELINE COMPLETED")
print("\n================================================")



