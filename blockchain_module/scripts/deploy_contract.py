from solcx import compile_standard, install_solc
from web3 import Web3
import json
import os

#-----------------------------------
# INSTALL SOLIDITY VERSION 0.8.0
#-----------------------------------

install_solc("0.8.0")


#-------------------------------
#SET SOLIDITY VERSION
#------------------------------------

#set_solc_version("0.8.0")


#----------------------------------------
# READ SMART CONTRACT 
#----------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
contract_path = os.path.join(
    BASE_DIR,
    "..",
    "contracts",
    "IDSLogStorage.sol"
)
with open(contract_path,"r") as file:
    contract_source_code = file.read()


#--------------------------------------------
# COMPILE CONTRACT
#---------------------------------------------

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {
            "IDSLogStorage.sol":{
                "content": contract_source_code
            }
    },

    "settings":{
        "outputSelection":{
            "*":{
                "*":["abi","evm.bytecode"]
                }
            }
        }
    },
    solc_version="0.8.0"
)

#SAVE ABI

Saving_path = os.path.join(
    BASE_DIR,
    "..",
    "abi",
    "IDSLogStorage.json"
)
with open(Saving_path,"w") as abi_file:
    json.dump(
        compiled_sol["contracts"]["IDSLogStorage.sol"]["IDSLogStorage"]["abi"],
        abi_file,
        indent=2
    )

#------------------------------------------------------
# CONNECT TO GANACHE 
#------------------------------------------------------

ganache_url = "http://192.168.111.1:7545"
W3 = Web3(Web3.HTTPProvider(ganache_url))

assert W3.is_connected(), "GANACHE NOT CONNECTED"

#--------------------------------------------
# LOAD ACCOUNT 
#---------------------------------------------

account = W3.eth.accounts[0]

#----------------------------------------------------------
# GET CONTRACT DATA
#--------------------------------------------------------------
"http://192.168.111.1:7545"
abi = compiled_sol["contracts"]["IDSLogStorage.sol"]["IDSLogStorage"]["abi"]
bytecode = compiled_sol["contracts"]["IDSLogStorage.sol"]["IDSLogStorage"]["evm"]["bytecode"]["object"]

#-----------------------------------------------------
# DEPLOY CONTRACT
#--------------------------------------------------------

IDSContract = W3.eth.contract(abi=abi, bytecode=bytecode)

tx_hash = IDSContract.constructor().transact({
    "from": account
})


tx_receipt = W3.eth.wait_for_transaction_receipt(tx_hash)

print("SMART CONTRACT DEPLOYED SUCCESSFULLY")
print("CONTRACT_ADDRESS=",tx_receipt.contractAddress)
print(f"DEPLOYED_ACCOUNT={account}")
