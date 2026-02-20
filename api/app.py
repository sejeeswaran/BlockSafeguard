"""
BSGuard — Production DDoS Cybersecurity Backend (Vercel Serverless)
Self-contained Flask app with AWS, Firebase, and Ethereum blockchain integration.
All external integrations use lazy imports + try-except for graceful degradation.
"""

import os
import time
import json
import hashlib
import logging
from collections import defaultdict

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "bsguard-vercel-secret")

# ---------------------------------------------------------------------------
# In-memory state (per invocation — serverless, so resets between cold starts)
# ---------------------------------------------------------------------------
requests_per_ip: dict = defaultdict(list)
blocked_ips_memory: set = set()
DDOS_THRESHOLD_10S = 20   # max requests in 10 seconds
DDOS_THRESHOLD_1S = 10    # max requests in 1 second
DDOS_THRESHOLD_TOTAL = 50 # max total requests in 60 seconds

ERR_MISSING_IP = "Missing 'ip' field"
ERR_INTERNAL = "Internal server error"

# ---------------------------------------------------------------------------
# Contract ABI (embedded to avoid file-path issues on Vercel)
# ---------------------------------------------------------------------------
CONTRACT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "string", "name": "ip", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "reason", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "Blacklisted",
        "type": "event",
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_ip", "type": "string"},
            {"internalType": "string", "name": "_reason", "type": "string"},
        ],
        "name": "addIP",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "name": "blacklist",
        "outputs": [
            {"internalType": "string", "name": "ip", "type": "string"},
            {"internalType": "string", "name": "reason", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getAllBlockedIPs",
        "outputs": [
            {
                "components": [
                    {"internalType": "string", "name": "ip", "type": "string"},
                    {"internalType": "string", "name": "reason", "type": "string"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                ],
                "internalType": "struct BlockSafeguard.BlockedIP[]",
                "name": "",
                "type": "tuple[]",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "getIP",
        "outputs": [
            {"internalType": "string", "name": "ip", "type": "string"},
            {"internalType": "string", "name": "reason", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getLength",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "string", "name": "_ip", "type": "string"}],
        "name": "isBlocked",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]


# =========================================================================
#  Helper: Firebase Firestore client (lazy init)
# =========================================================================
_firebase_db = None


def _get_firestore_db():
    """Return a Firestore client, initialising Firebase lazily on first call."""
    global _firebase_db
    if _firebase_db is not None:
        return _firebase_db

    import firebase_admin
    from firebase_admin import credentials, firestore

    if not firebase_admin._apps:
        sa_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
        if sa_json:
            cred = credentials.Certificate(json.loads(sa_json))
            firebase_admin.initialize_app(cred)
        else:
            sa_path = os.environ.get("FIREBASE_SERVICE_ACCOUNT")
            if sa_path and os.path.exists(sa_path):
                cred = credentials.Certificate(sa_path)
                firebase_admin.initialize_app(cred)
            else:
                raise RuntimeError("No Firebase credentials configured")

    _firebase_db = firestore.client()
    return _firebase_db


# =========================================================================
#  Helper: Blockchain (web3) operations
# =========================================================================
def _get_web3_contract():
    """Return (web3, contract, account, private_key) tuple."""
    from web3 import Web3

    infura_url = os.environ.get("INFURA_URL")
    contract_address = os.environ.get("CONTRACT_ADDRESS")
    account = os.environ.get("WALLET_ADDRESS")
    private_key = os.environ.get("WALLET_PRIVATE_KEY")

    if not all([infura_url, contract_address, account, private_key]):
        raise RuntimeError("Blockchain env vars not fully configured")

    web3 = Web3(Web3.HTTPProvider(infura_url))
    contract = web3.eth.contract(address=contract_address, abi=CONTRACT_ABI)
    return web3, contract, account, private_key


def _log_ip_to_blockchain(ip, reason):
    """Write an IP + reason to the smart contract."""
    web3, contract, account, private_key = _get_web3_contract()
    txn = contract.functions.addIP(ip, reason).build_transaction(
        {
            "from": account,
            "nonce": web3.eth.get_transaction_count(account),
            "gas": 200000,
            "gasPrice": web3.to_wei("10", "gwei"),
        }
    )
    signed = web3.eth.account.sign_transaction(txn, private_key=private_key)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    return web3.to_hex(tx_hash)


def _get_blocked_ips_from_blockchain():
    """Read all blocked IPs from the smart contract."""
    web3, contract, _, _ = _get_web3_contract()
    length = contract.functions.getLength().call()
    blocked = []
    for i in range(length):
        ip, reason, timestamp = contract.functions.getIP(i).call()
        blocked.append({"ip": ip, "reason": reason, "timestamp": timestamp})
    return blocked


# =========================================================================
#  Helper: AWS NACL blocking
# =========================================================================
_rule_counter = 100


def _block_ip_aws(ip):
    """Create a DENY rule on the AWS Network ACL for the given IP."""
    global _rule_counter
    import boto3

    nacl_id = os.environ.get("AWS_NACL_ID")
    region = os.environ.get("AWS_REGION")
    if not nacl_id or not region:
        raise RuntimeError("AWS_NACL_ID / AWS_REGION not configured")

    ec2 = boto3.client("ec2", region_name=region)
    ec2.create_network_acl_entry(
        NetworkAclId=nacl_id,
        RuleNumber=_rule_counter,
        Protocol="-1",
        RuleAction="deny",
        Egress=False,
        CidrBlock=f"{ip}/32",
    )
    _rule_counter += 1
    return True


# =========================================================================
#  Helper: DDoS detection logic
# =========================================================================
def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _detect_ddos(ip):
    """
    Returns (is_attack: bool, reason: str) based on request-frequency
    thresholds and suspicious-pattern heuristics.
    """
    now = time.time()
    requests_per_ip[ip] = [t for t in requests_per_ip[ip] if (now - t) < 60]
    requests_per_ip[ip].append(now)

    recent_10s = len([r for r in requests_per_ip[ip] if now - r < 10])
    recent_1s = len([r for r in requests_per_ip[ip] if now - r < 1])
    total_60s = len(requests_per_ip[ip])

    if recent_1s >= DDOS_THRESHOLD_1S:
        return True, f"Rapid burst: {recent_1s} requests in 1 second"
    if recent_10s >= DDOS_THRESHOLD_10S:
        return True, f"High frequency: {recent_10s} requests in 10 seconds"
    if total_60s >= DDOS_THRESHOLD_TOTAL:
        return True, f"Sustained flood: {total_60s} requests in 60 seconds"

    # Heuristic: private/internal IP ranges often used in spoofed attacks
    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.0."):
        return True, "Suspicious source: private/internal IP range"

    return False, "Normal traffic"


# =========================================================================
#  ROUTES
# =========================================================================

# ---- GET / ---------------------------------------------------------------
@app.route("/", methods=["GET"])
def health_check():
    return jsonify(
        {
            "status": "ok",
            "message": "BSGuard backend running",
            "version": "2.0.0",
            "timestamp": _now(),
        }
    )


# ---- POST /detect --------------------------------------------------------
@app.route("/detect", methods=["POST"])
def detect():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        is_attack, reason = _detect_ddos(ip)
        logger.info(f"[Detect] IP={ip} attack={is_attack} reason={reason}")

        return jsonify(
            {
                "ip": ip,
                "is_attack": is_attack,
                "reason": reason,
                "timestamp": _now(),
            }
        )
    except Exception as e:
        logger.error(f"[Detect] Error: {e}")
        return jsonify({"error": "Detection failed", "details": str(e)}), 500


# ---- POST /block ---------------------------------------------------------
@app.route("/block", methods=["POST"])
def block():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        method = "simulated"
        note = None

        try:
            _block_ip_aws(ip)
            method = "AWS NACL"
            logger.info(f"[Block] IP {ip} blocked via AWS NACL")
        except Exception as aws_err:
            note = f"AWS fallback: {str(aws_err)}"
            logger.warning(f"[Block] AWS not available, simulated block for {ip}: {aws_err}")

        blocked_ips_memory.add(ip)

        result = {
            "ip": ip,
            "action": "blocked",
            "method": method,
            "timestamp": _now(),
        }
        if note:
            result["note"] = note

        return jsonify(result)
    except Exception as e:
        logger.error(f"[Block] Error: {e}")
        return jsonify({"error": "Blocking failed", "details": str(e)}), 500


# ---- POST /log -----------------------------------------------------------
@app.route("/log", methods=["POST"])
def log_attack():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        reason = data.get("reason", "Suspicious activity")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        result = {"ip": ip, "reason": reason}

        # Firebase Firestore logging
        try:
            db = _get_firestore_db()
            db.collection("blocked_ips").document().set(
                {
                    "ip": ip,
                    "reason": reason,
                    "timestamp": _now(),
                }
            )
            result["firebase"] = "logged"
            logger.info(f"[Log] Firebase logged IP {ip}")
        except Exception as fb_err:
            result["firebase"] = f"skipped: {str(fb_err)}"
            logger.warning(f"[Log] Firebase error: {fb_err}")

        result["timestamp"] = _now()
        return jsonify(result)
    except Exception as e:
        logger.error(f"[Log] Error: {e}")
        return jsonify({"error": "Logging failed", "details": str(e)}), 500


# ---- POST /blockchain-log ------------------------------------------------
@app.route("/blockchain-log", methods=["POST"])
def blockchain_log():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        reason = data.get("reason", "Suspicious activity")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        result = {"ip": ip, "reason": reason}

        try:
            tx_hash = _log_ip_to_blockchain(ip, reason)
            result["blockchain"] = "logged"
            result["tx_hash"] = tx_hash
            logger.info(f"[Blockchain] Logged IP {ip} — TX {tx_hash}")
        except Exception as bc_err:
            result["blockchain"] = f"skipped: {str(bc_err)}"
            logger.warning(f"[Blockchain] Error: {bc_err}")

        result["timestamp"] = _now()
        return jsonify(result)
    except Exception as e:
        logger.error(f"[Blockchain-Log] Error: {e}")
        return jsonify({"error": "Blockchain logging failed", "details": str(e)}), 500


# ---- GET /status ----------------------------------------------------------
@app.route("/status", methods=["GET"])
def status():
    try:
        blockchain_ips = []
        blockchain_status = "unknown"

        try:
            blockchain_ips = _get_blocked_ips_from_blockchain()
            blockchain_status = "connected"
        except Exception as bc_err:
            blockchain_status = f"unavailable: {str(bc_err)}"

        return jsonify(
            {
                "system": "BSGuard v2.0.0",
                "status": "active",
                "blockchain": blockchain_status,
                "blocked_ips_count": len(blockchain_ips),
                "blocked_ips": blockchain_ips[-10:],  # last 10
                "in_memory_blocked": list(blocked_ips_memory),
                "timestamp": _now(),
            }
        )
    except Exception as e:
        logger.error(f"[Status] Error: {e}")
        return jsonify({"error": ERR_INTERNAL, "details": str(e)}), 500


# ---- GET /api/status/<api_key> --------------------------------------------
@app.route("/api/status/<api_key>", methods=["GET"])
def api_status(api_key):
    try:
        if api_key != os.environ.get("BSGUARD_API_KEY", "demo_key"):
            return jsonify({"error": "Invalid API key"}), 401

        blockchain_ips = []
        try:
            blockchain_ips = _get_blocked_ips_from_blockchain()
        except Exception:
            pass

        return jsonify(
            {
                "status": "active",
                "blocked_ips_count": len(blockchain_ips),
                "total_requests": sum(len(v) for v in requests_per_ip.values()),
                "blocked_ips": blockchain_ips[-10:],
                "timestamp": _now(),
            }
        )
    except Exception as e:
        logger.error(f"[API Status] Error: {e}")
        return jsonify({"error": ERR_INTERNAL}), 500


# ---- POST /api/check ------------------------------------------------------
@app.route("/api/check", methods=["POST"])
def api_check():
    try:
        data = request.get_json(force=True)
        api_key = data.get("api_key")
        ip = data.get("ip", request.headers.get("X-Forwarded-For", request.remote_addr))

        if api_key != os.environ.get("BSGUARD_API_KEY", "demo_key"):
            return jsonify({"error": "Invalid API key"}), 401

        if ip in blocked_ips_memory:
            return (
                jsonify(
                    {
                        "action": "block",
                        "reason": "IP in blocked list",
                        "timestamp": _now(),
                    }
                ),
                403,
            )

        return jsonify({"action": "allow", "status": "clean", "timestamp": _now()})
    except Exception as e:
        logger.error(f"[API Check] Error: {e}")
        return jsonify({"error": ERR_INTERNAL}), 500


# =========================================================================
#  WSGI export for Vercel — DO NOT add app.run()
# =========================================================================
application = app
