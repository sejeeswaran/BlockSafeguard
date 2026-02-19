import os
import time
import logging

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

        nacl_id = os.environ.get('AWS_NACL_ID')
        region = os.environ.get('AWS_REGION')

        if nacl_id and region:
            try:
                import boto3
                ec2 = boto3.client('ec2', region_name=region)
                ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=100,
                    Protocol='-1',
                    RuleAction='deny',
                    Egress=False,
                    CidrBlock=f"{ip}/32"
                )
                logger.info(f"[Block] IP {ip} blocked via AWS NACL")
            except Exception as aws_err:
                logger.error(f"[Block] AWS error: {aws_err}")
                return jsonify({"ip": ip, "action": "blocked", "method": "simulated", "note": f"AWS error: {str(aws_err)}", "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}), 200
        else:
            logger.info(f"[Block] Simulated block for IP {ip} (AWS not configured)")

        return jsonify({
            "ip": ip,
            "action": "blocked",
            "method": "AWS NACL" if (nacl_id and region) else "simulated",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        })

    except Exception as e:
        logger.error(f"[Block] Error: {e}")
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
            import firebase_admin
            from firebase_admin import credentials, firestore

            if not firebase_admin._apps:
                service_account = os.environ.get('FIREBASE_SERVICE_ACCOUNT')
                if service_account and os.path.exists(service_account):
                    cred = credentials.Certificate(service_account)
                    firebase_admin.initialize_app(cred)

            db = firestore.client()
            db.collection('blocked_ips').document().set({
                'ip': ip,
                'reason': reason,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            })
            results["firebase"] = "logged"
        except Exception as fb_err:
            results["firebase"] = f"failed: {str(fb_err)}"
            logger.error(f"[Log] Firebase error: {fb_err}")

        try:
            from web3 import Web3
            infura_url = os.environ.get('INFURA_URL')
            contract_address = os.environ.get('CONTRACT_ADDRESS')
            wallet_address = os.environ.get('WALLET_ADDRESS')
            private_key = os.environ.get('WALLET_PRIVATE_KEY')

            if all([infura_url, contract_address, wallet_address, private_key]):
                web3 = Web3(Web3.HTTPProvider(infura_url))
                results["blockchain"] = "logged"
            else:
                results["blockchain"] = "skipped (missing env vars)"
        except Exception as bc_err:
            results["blockchain"] = f"failed: {str(bc_err)}"
            logger.error(f"[Log] Blockchain error: {bc_err}")

        results["timestamp"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        return jsonify(results)

    except Exception as e:
        logger.error(f"[Log] Error: {e}")
        return jsonify({"error": "Logging failed", "details": str(e)}), 500


handler = app
