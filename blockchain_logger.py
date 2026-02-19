from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

# --- Load configuration from environment variables ----
infura_url = os.environ.get('INFURA_URL')
contract_address = os.environ.get('CONTRACT_ADDRESS')

# Load ABI from file
with open('abi.json', 'r') as f:
    contract_abi = json.load(f)

account = os.environ.get('WALLET_ADDRESS')
private_key = os.environ.get('WALLET_PRIVATE_KEY')

def log_suspicious_ip(ip, reason):
    web3 = Web3(Web3.HTTPProvider(infura_url))
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    txn = contract.functions.addIP(ip, reason).build_transaction({
        'from': account,
        'nonce': web3.eth.get_transaction_count(account),
        'gas': 200000,
        'gasPrice': web3.to_wei('10', 'gwei')
    })
    signed_txn = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"[Blockchain] Logged {ip} - Reason: {reason} - TX: {web3.to_hex(tx_hash)}")

def get_blocked_ips_from_blockchain():
    """
    Retrieve all blocked IPs from the blockchain smart contract.
    """
    try:
        web3 = Web3(Web3.HTTPProvider(infura_url))
        contract = web3.eth.contract(address=contract_address, abi=contract_abi)
        length = contract.functions.getLength().call()
        blocked_list = []
        for i in range(length):
            ip, reason, timestamp = contract.functions.getIP(i).call()
            blocked_list.append({
                "ip": ip,
                "reason": reason,
                "timestamp": timestamp
            })
        return blocked_list
    except Exception as e:
        print(f"[Blockchain] Error retrieving blocked IPs: {e}")
        return []
