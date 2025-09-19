from web3 import Web3

# --- Configure these variables (get from Remix after contract deployment) ----
infura_url = 'https://sepolia.infura.io/v3/cda4d32c4bc24ed6828b761dffdf6d90'
contract_address = '0x5a4ED6ce4b19EB10BCc658190FBA0087e860ee92'
contract_abi = [
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "ip",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "reason",
				"type": "string"
			}
		],
		"name": "addIP",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "string",
				"name": "ip",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "reason",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "Blacklisted",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "blacklist",
		"outputs": [
			{
				"internalType": "string",
				"name": "ip",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "reason",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "index",
				"type": "uint256"
			}
		],
		"name": "getIP",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getLength",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]# Auto-updated ABI from abi.json
account = '0x270A9189557868B5e6dd369FdC024F7997D8A8be'
private_key = 'TEST ACCOUNT PVT KEY'   # Use DEDICATED TEST ACCOUNT ONLY

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
