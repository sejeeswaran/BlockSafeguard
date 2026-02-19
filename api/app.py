import sys
import os
import time
import json
import logging

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(ROOT_DIR, '.env'))

from flask import Flask, request, jsonify

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-fallback-key')

ERR_MISSING_IP = "Missing 'ip' field"


@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "ok",
        "message": "BSGuard backend running",
        "version": "1.0.0"
    })


@app.route('/detect', methods=['POST'])
def detect_ddos():
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        is_attack = False
        reason = "Normal traffic"

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


@app.route('/block', methods=['POST'])
def block_ip():
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

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


@app.route('/log', methods=['POST'])
def log_activity():
    try:
        data = request.get_json(force=True)
        ip = data.get('ip')
        reason = data.get('reason', 'Suspicious activity')

        if not ip:
            return jsonify({"error": ERR_MISSING_IP}), 400

        results = {"ip": ip, "reason": reason}

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


handler = app
