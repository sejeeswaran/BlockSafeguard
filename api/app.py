"""
BSGuard — Production DDoS Cybersecurity Backend (Vercel Serverless)
Self-contained Flask app with HTML pages + API endpoints.
Integrates AWS, Firebase, and Ethereum blockchain with lazy imports.
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from collections import defaultdict

from flask import Flask, request, jsonify, render_template, session, redirect, url_for

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
# Flask App — point template & static folders to project root level
# ---------------------------------------------------------------------------
_base_dir = Path(__file__).resolve().parent.parent  # project root (one level up from api/)

app = Flask(
    __name__,
    template_folder=str(_base_dir / "templates"),
    static_folder=str(_base_dir / "static"),
)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "bsguard-vercel-secret")

# ---------------------------------------------------------------------------
# In-memory state (per invocation — serverless resets between cold starts)
# ---------------------------------------------------------------------------
requests_per_ip: dict = defaultdict(list)
blocked_ips_memory: set = set()
unblocked_ips: list = []
DDOS_THRESHOLD_10S = 20
DDOS_THRESHOLD_1S = 10
DDOS_THRESHOLD_TOTAL = 50

ERR_MISSING_IP = "Missing 'ip' field"
ERR_INTERNAL = "Internal server error"
SIGNUP_TEMPLATE = "signup.html"

# ---------------------------------------------------------------------------
# Contract ABI (embedded — avoids file-path issues on Vercel)
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
#  Helper: Firebase
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
        # Try FIREBASE_SERVICE_ACCOUNT_JSON first, then FIREBASE_SERVICE_ACCOUNT
        sa_raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON") or os.environ.get("FIREBASE_SERVICE_ACCOUNT")
        if sa_raw and sa_raw.strip().startswith("{"):
            # Value is JSON content (pasted directly into env var)
            cred = credentials.Certificate(json.loads(sa_raw))
            firebase_admin.initialize_app(cred)
        elif sa_raw and os.path.exists(sa_raw):
            # Value is a file path (local development)
            cred = credentials.Certificate(sa_raw)
            firebase_admin.initialize_app(cred)
        else:
            raise RuntimeError("No Firebase credentials configured")

    _firebase_db = firestore.client()
    return _firebase_db


def _firebase_log_activity(collection_name, data):
    """Log data to a Firestore collection."""
    db = _get_firestore_db()
    db.collection(collection_name).document().set(data)


def _firebase_signup_user(email, password, extra_data):
    """Create a Firebase Auth user and store profile in Firestore."""
    from firebase_admin import auth
    user = auth.create_user(email=email, password=password)
    uid = user.uid
    db = _get_firestore_db()
    db.collection("users").document(uid).set(extra_data)
    return uid


def _firebase_get_user_by_email(email):
    """Look up a user by email from Firebase Auth + Firestore."""
    from firebase_admin import auth
    user = auth.get_user_by_email(email)
    uid = user.uid
    db = _get_firestore_db()
    doc = db.collection("users").document(uid).get()
    if doc.exists:
        return doc.to_dict()
    return None


def _firebase_verify_password(email, password):
    """Verify password via Firebase REST API."""
    import requests as http_requests
    api_key = os.environ.get("FIREBASE_API_KEY")
    if not api_key:
        return False
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    try:
        resp = http_requests.post(url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True,
        })
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


# =========================================================================
#  Helper: Blockchain (web3)
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
    _, contract, _, _ = _get_web3_contract()
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


def _unblock_ip_aws(ip):
    """Remove a NACL rule for the given IP (simplified)."""
    import boto3

    nacl_id = os.environ.get("AWS_NACL_ID")
    region = os.environ.get("AWS_REGION")
    if not nacl_id or not region:
        raise RuntimeError("AWS_NACL_ID / AWS_REGION not configured")

    # In serverless we can't track rule numbers across invocations,
    # so this is a best-effort approach
    logger.info(f"[AWS] Unblock requested for {ip} (manual NACL cleanup may be needed)")


# =========================================================================
#  Helper: DDoS detection logic
# =========================================================================
def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _detect_ddos(ip):
    """Returns (is_attack: bool, reason: str)."""
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

    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("192.168.0."):
        return True, "Suspicious source: private/internal IP range"

    return False, "Normal traffic"


# =========================================================================
#  PAGE ROUTES (HTML templates)
# =========================================================================

@app.route("/", methods=["GET"])
def index():
    first_name = session.get("first_name")
    return render_template("index.html", first_name=first_name)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        email = request.form.get("email")
        try:
            _firebase_log_activity("login_activities", {
                "email": email,
                "timestamp": _now(),
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            })
            user_data = _firebase_get_user_by_email(email)
            if user_data:
                session["first_name"] = user_data.get("first_name", "User")
                session["email"] = email
                return redirect(url_for("index"))
            else:
                message = "User not found."
        except Exception as e:
            logger.error(f"Login error: {e}")
            message = "Error during login."
    return render_template("login.html", message=message)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    message = None
    if request.method == "POST":
        first_name = request.form.get("firstName")
        last_name = request.form.get("lastName")
        email = request.form.get("email")
        company = request.form.get("company")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmPassword")
        terms = request.form.get("terms") == "on"

        enable_notifications = request.form.get("enableNotifications") == "on"
        notification_email = request.form.get("notificationEmail") or email
        gmail_app_password = request.form.get("gmailAppPassword")

        if enable_notifications and not gmail_app_password:
            message = "Gmail App Password is required when notifications are enabled."
            return render_template(SIGNUP_TEMPLATE, message=message)
        if password != confirm_password:
            message = "Passwords do not match."
            return render_template(SIGNUP_TEMPLATE, message=message)
        if not terms:
            message = "You must accept the terms and conditions."
            return render_template(SIGNUP_TEMPLATE, message=message)

        try:
            user_id = _firebase_signup_user(email, password, {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "company": company,
                "terms_accepted": terms,
                "timestamp": _now(),
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "enable_notifications": enable_notifications,
                "notification_email": notification_email,
                "gmail_app_password": gmail_app_password,
            })
            logger.info(f"User created with UID: {user_id}")
            _firebase_log_activity("signup_activities", {
                "email": email,
                "timestamp": _now(),
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            })
            session["first_name"] = first_name
            return redirect(url_for("index"))
        except Exception as e:
            logger.error(f"Signup error: {e}")
            message = "Signup failed. Try again."

    return render_template(SIGNUP_TEMPLATE, message=message)


@app.route("/logout")
def logout():
    session.pop("first_name", None)
    session.pop("email", None)
    return redirect(url_for("index"))


@app.route("/status", methods=["GET"])
def status_page():
    """Serve the HTML status dashboard."""
    blocked_ips_list = []
    try:
        blocked_ips_list = _get_blocked_ips_from_blockchain()
    except Exception as e:
        logger.warning(f"Could not load blockchain IPs for status page: {e}")

    return render_template(
        "status.html",
        status="Service running",
        blocked_count=len(blocked_ips_list),
        blocked_ips=blocked_ips_list,
        unblocked_count=len(unblocked_ips),
        unblocked_ips=unblocked_ips,
    )


@app.route("/unblock/<ip>", methods=["POST"])
def unblock_ip_route(ip):
    if "first_name" not in session or "email" not in session:
        return "Unauthorized", 403

    password = request.form.get("password")
    email = session["email"]

    if _firebase_verify_password(email, password):
        try:
            _unblock_ip_aws(ip)
        except Exception as e:
            logger.warning(f"AWS unblock failed: {e}")
        blocked_ips_memory.discard(ip)
        unblocked_ips.append({
            "ip": ip,
            "timestamp": _now(),
            "unblocked_by": session.get("first_name", "Unknown"),
        })
        if len(unblocked_ips) > 50:
            unblocked_ips.pop(0)
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Invalid password"}), 403


@app.route("/block/<ip>", methods=["POST"])
def block_ip_route(ip):
    if "first_name" not in session or "email" not in session:
        return "Unauthorized", 403

    password = request.form.get("password")
    email = session["email"]

    if _firebase_verify_password(email, password):
        try:
            _log_ip_to_blockchain(ip, "Manual block")
        except Exception as e:
            logger.error(f"Blockchain logging failed for {ip}: {e}")
        try:
            _block_ip_aws(ip)
        except Exception as e:
            logger.error(f"AWS NACL blocking failed for {ip}: {e}")
        blocked_ips_memory.add(ip)
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Invalid password"}), 403


# =========================================================================
#  API ROUTES (JSON endpoints)
# =========================================================================

@app.route("/api/health", methods=["GET"])
def api_health():
    """JSON health check for programmatic access."""
    return jsonify({
        "status": "ok",
        "message": "BSGuard backend running",
        "version": "2.0.0",
        "timestamp": _now(),
    })


@app.route("/detect", methods=["POST"])
def detect():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        is_attack, reason = _detect_ddos(ip)
        logger.info(f"[Detect] IP={ip} attack={is_attack} reason={reason}")
        return jsonify({"ip": ip, "is_attack": is_attack, "reason": reason, "timestamp": _now()})
    except Exception as e:
        logger.error(f"[Detect] Error: {e}")
        return jsonify({"error": "Detection failed", "details": str(e)}), 500


@app.route("/block", methods=["POST"])
def block_api():
    """API endpoint to block an IP (JSON body)."""
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
        except Exception as aws_err:
            note = f"AWS fallback: {str(aws_err)}"
            logger.warning(f"[Block] AWS not available for {ip}: {aws_err}")

        blocked_ips_memory.add(ip)
        result = {"ip": ip, "action": "blocked", "method": method, "timestamp": _now()}
        if note:
            result["note"] = note
        return jsonify(result)
    except Exception as e:
        logger.error(f"[Block] Error: {e}")
        return jsonify({"error": "Blocking failed", "details": str(e)}), 500


@app.route("/log", methods=["POST"])
def log_attack():
    try:
        data = request.get_json(force=True)
        ip = data.get("ip")
        reason = data.get("reason", "Suspicious activity")
        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        result = {"ip": ip, "reason": reason}
        try:
            db = _get_firestore_db()
            db.collection("blocked_ips").document().set({"ip": ip, "reason": reason, "timestamp": _now()})
            result["firebase"] = "logged"
        except Exception as fb_err:
            result["firebase"] = f"skipped: {str(fb_err)}"

        result["timestamp"] = _now()
        return jsonify(result)
    except Exception as e:
        logger.error(f"[Log] Error: {e}")
        return jsonify({"error": "Logging failed", "details": str(e)}), 500


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
        except Exception as bc_err:
            result["blockchain"] = f"skipped: {str(bc_err)}"

        result["timestamp"] = _now()
        return jsonify(result)
    except Exception as e:
        logger.error(f"[Blockchain-Log] Error: {e}")
        return jsonify({"error": "Blockchain logging failed", "details": str(e)}), 500


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

        return jsonify({
            "status": "active",
            "blocked_ips_count": len(blockchain_ips),
            "total_requests": sum(len(v) for v in requests_per_ip.values()),
            "blocked_ips": blockchain_ips[-10:],
            "timestamp": _now(),
        })
    except Exception as e:
        logger.error(f"[API Status] Error: {e}")
        return jsonify({"error": ERR_INTERNAL}), 500


@app.route("/api/check", methods=["POST"])
def api_check():
    try:
        data = request.get_json(force=True)
        api_key = data.get("api_key")
        ip = data.get("ip", request.headers.get("X-Forwarded-For", request.remote_addr))

        if api_key != os.environ.get("BSGUARD_API_KEY", "demo_key"):
            return jsonify({"error": "Invalid API key"}), 401

        if ip in blocked_ips_memory:
            return jsonify({"action": "block", "reason": "IP in blocked list", "timestamp": _now()}), 403

        return jsonify({"action": "allow", "status": "clean", "timestamp": _now()})
    except Exception as e:
        logger.error(f"[API Check] Error: {e}")
        return jsonify({"error": ERR_INTERNAL}), 500


# =========================================================================
#  WSGI export for Vercel — DO NOT add app.run()
# =========================================================================
application = app
