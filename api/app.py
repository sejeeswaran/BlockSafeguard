# =============================================================================
# BSGuard — Vercel Serverless Flask API
# =============================================================================
# This file is the serverless entry point for Vercel's @vercel/python runtime.
# Vercel imports this module and looks for the `app` WSGI variable.
# Do NOT call app.run() — Vercel handles serving.
# =============================================================================

import sys
import os
import time
import json
import logging

# ---------------------------------------------------------------------------
# Path setup: Add project root so we can import existing modules
# (firebase_client, blockchain_logger, aws_blocker)
# ---------------------------------------------------------------------------
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

# ---------------------------------------------------------------------------
# Load environment variables from .env (useful for local testing)
# On Vercel, env vars are set in the Dashboard → Project Settings
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT_DIR, '.env'))

from flask import Flask, request, jsonify

# ---------------------------------------------------------------------------
# Configure logging (stderr only — no file writes in serverless)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Create Flask app — this is the WSGI variable Vercel looks for
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-fallback-key')

# Constants for repeated string literals
ERR_MISSING_IP = "Missing 'ip' field"


# ===========================================================================
# Route: GET / — Health check
# ===========================================================================
@app.route('/', methods=['GET'])
def health_check():
    """Return a simple JSON health check confirming the API is running."""
    return jsonify({
        "status": "ok",
        "message": "BSGuard backend running",
        "version": "1.0.0"
    })


# ===========================================================================
# Route: POST /detect — Simulate DDoS detection
# ===========================================================================
@app.route('/detect', methods=['POST'])
def detect_ddos():
    """
    Simulate DDoS detection for a given IP address.
    Expects JSON body: { "ip": "x.x.x.x" }
    In production, this checks request frequency against a threshold.
    """
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        # Simulate detection logic (threshold-based)
        is_attack = False
        reason = "Normal traffic"

        # Simple simulation: IPs starting with "10." flagged as suspicious
        if ip.startswith("10."):
            is_attack = True
            reason = "Suspicious traffic pattern detected"

        logger.info(f"[Detect] IP: {ip}, Attack: {is_attack}, Reason: {reason}")

        return jsonify({
            "ip": ip,
            "is_attack": is_attack,
            "reason": reason,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        })

    except Exception as e:
        logger.error(f"[Detect] Error: {e}")
        return jsonify({"error": "Detection failed", "details": str(e)}), 500


# ===========================================================================
# Route: POST /block — Block IP via AWS NACL
# ===========================================================================
@app.route('/block', methods=['POST'])
def block_ip():
    """
    Block an IP address using AWS Network ACL via boto3.
    Expects JSON body: { "ip": "x.x.x.x" }
    Requires AWS_NACL_ID and AWS_REGION environment variables.
    """
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        # Import AWS blocker from project root
        from aws_blocker import block_ip as aws_block_ip
        aws_block_ip(ip)

        logger.info(f"[Block] IP {ip} blocked via AWS NACL")

        return jsonify({
            "ip": ip,
            "action": "blocked",
            "method": "AWS NACL",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        })

    except Exception as e:
        logger.error(f"[Block] Error blocking IP: {e}")
        return jsonify({"error": "Blocking failed", "details": str(e)}), 500


# ===========================================================================
# Route: POST /log — Log to Firebase and Blockchain
# ===========================================================================
@app.route('/log', methods=['POST'])
def log_activity():
    """
    Log a suspicious IP to both Firebase Firestore and the blockchain.
    Expects JSON body: { "ip": "x.x.x.x", "reason": "DDoS detected" }
    Requires Firebase service account and Web3/Infura env vars.
    """
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')
        reason = data.get('reason', 'Suspicious activity')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        results = {"ip": ip, "reason": reason}

        # --- Firebase Logging ---
        try:
            from firebase_client import log_activity as fb_log
            fb_log('blocked_ips', {
                'ip': ip,
                'reason': reason,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            })
            results["firebase"] = "logged"
            logger.info(f"[Log] Firebase: logged IP {ip}")
        except Exception as fb_err:
            results["firebase"] = f"failed: {str(fb_err)}"
            logger.error(f"[Log] Firebase error: {fb_err}")

        # --- Blockchain Logging ---
        try:
            from blockchain_logger import log_suspicious_ip
            log_suspicious_ip(ip, reason)
            results["blockchain"] = "logged"
            logger.info(f"[Log] Blockchain: logged IP {ip}")
        except Exception as bc_err:
            results["blockchain"] = f"failed: {str(bc_err)}"
            logger.error(f"[Log] Blockchain error: {bc_err}")

        results["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        return jsonify(results)

    except Exception as e:
        logger.error(f"[Log] Error: {e}")
        return jsonify({"error": "Logging failed", "details": str(e)}), 500


# ===========================================================================
# Vercel Handler — Export the app variable (required by @vercel/python)
# ===========================================================================
# Vercel's Python runtime imports this file and looks for `app`.
# Do NOT add app.run() here — Vercel handles serving automatically.
handler = app
