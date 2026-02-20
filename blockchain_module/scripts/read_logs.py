from web3 import Web3
import json


ganache_url = "http://192.168.111.1:7545"
Web3= Web3(Web3.HTTPProvider(ganache_url))


with open("../abi/IDSLogStorage.json","r") as abi_file:
    abi = json.load(abi_file)

contract_address = Web3.to_checksum_address(
    "0xBd2d1150392A6E664fa57dAC3Fd13558A5c6224f"
)

contract = Web3.eth.contract(
    address=contract_address,
    abi = abi
)

log_count = contract.functions.getLogCount().call()

print("TOTAL LOG COUNT", log_count)

for i in range(log_count):
    log = contract.functions.getLog(i).call()
    print(f"LOG{i}") 
    print("TimeStamp ",log[0])
    print("Source IP ",log[1])
    print("Dest IP   ",log[2])
    print("Protocol  ",log[3])
    print("Prediction",log[4])
    print("Attack    ",log[5])
    print("HASH      ",log[6])