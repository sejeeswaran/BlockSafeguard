from flask import Flask, request, render_template, session, redirect, url_for, jsonify

from collections import defaultdict
import time
import threading
import smtplib
from email.mime.text import MIMEText
import logging
import os
import requests
from dotenv import load_dotenv
from firebase_client import signup_user
from firebase_client import log_activity
from firebase_client import get_user_by_email

load_dotenv()

def verify_password(email, password):
    api_key = os.environ.get('FIREBASE_API_KEY')
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    data = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return True
        else:
            logger.warning(f"Password verification failed for {email}: {response.json()}")
            return False
    except Exception as e:
        logger.error(f"Error verifying password for {email}: {e}")
        return False

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blocksafeguard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

requests_per_ip = defaultdict(list)
DDOS_THRESHOLD = 9

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

SIGNUP_TEMPLATE = 'signup.html'
ERR_INVALID_API_KEY = "Invalid API key"
ERR_INTERNAL_SERVER = "Internal server error"

blocked_ips_proactive = set()
unblocked_ips = []

try:
    from blockchain_logger import get_blocked_ips_from_blockchain
    startup_blocked = get_blocked_ips_from_blockchain()
    for item in startup_blocked:
        blocked_ips_proactive.add(item['ip'])
    logger.info(f"Loaded {len(blocked_ips_proactive)} blocked IPs for proactive checking")
except Exception as e:
    logger.error(f"Failed to load blocked IPs for proactive checking: {e}")
    blocked_ips_proactive = set()

def send_attack_notification(ip, reason):
    from firebase_client import get_notification_settings

    settings = get_notification_settings()
    if not settings:
        logger.warning("No notification settings found in Firebase")
        return

    try:
        msg = MIMEText(f"""
DDoS Attack Detected!

IP Address: {ip}
Reason: {reason}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
Action: IP blocked at network level and logged to blockchain

BlockSafeguard DDoS Protection System
        """)
        msg['Subject'] = f'DDoS Attack Alert - IP {ip} Blocked'
        msg['From'] = settings['email_user']
        msg['To'] = settings['notification_email']

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(settings['email_user'], settings['email_pass'])
        server.sendmail(settings['email_user'], settings['notification_email'], msg.as_string())
        server.quit()
        logger.info(f"Attack notification sent for IP {ip} to {settings['notification_email']}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")


def handle_ddos(ip):
    logger.warning(f"DDoS detected from IP: {ip}")

    try:
        from blockchain_logger import log_suspicious_ip
        log_suspicious_ip(ip, "DDoS detected via threshold")
        logger.info(f"> Blockchain logging completed for IP {ip}")
    except Exception as e:
        logger.error(f"X Blockchain logging failed for IP {ip}: {e}")

    try:
        from aws_blocker import block_ip
        block_ip(ip)
        logger.info(f"> AWS NACL blocking initiated for IP {ip}")
    except Exception as e:
        logger.error(f"X AWS NACL blocking failed for IP {ip}: {e}")

    blocked_ips_proactive.add(ip)
    logger.info(f"> IP {ip} added to proactive blocking set")

    try:
        send_attack_notification(ip, "DDoS detected via threshold")
        logger.info(f"> Email notification sent for IP {ip}")
    except Exception as e:
        logger.error(f"X Email notification failed for IP {ip}: {e}")

    logger.warning(f" DDoS response completed for IP {ip}")

@app.before_request
def monitor_traffic():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = time.time()

    trusted_ips = ['127.0.0.1', 'localhost', '::1', '192.168.0.105', '10.200.241.254']
    if ip in trusted_ips:
        return

    if ip in blocked_ips_proactive:
        logger.warning(f"Proactive block: IP {ip} is in blocked list")
        return "Access Denied: Your IP has been blocked due to suspicious activity.", 403

    requests_per_ip[ip] = [t for t in requests_per_ip[ip] if (now - t) < 60]
    requests_per_ip[ip].append(now)

    current_count = len(requests_per_ip[ip])
    recent_requests = len([r for r in requests_per_ip[ip] if now - r < 10])

    if recent_requests >= 20:
        logger.warning(f"[DDOS TRIGGER] IP {ip} sent {recent_requests} requests in 10s")
        handle_ddos(ip)
    elif len([r for r in requests_per_ip[ip] if now - r < 1]) >= 10:
        logger.warning(f"[RAPID ATTACK] IP {ip} sent 10+ requests/second")
        handle_ddos(ip)
    elif current_count >= 50:
        logger.warning(f"[HIGH VOLUME] IP {ip} reached {current_count} total requests")
        handle_ddos(ip)

    if current_count > 2:
        logger.info(f"[REQUEST TRACK] IP {ip}: {current_count} requests, last 10s: {len([r for r in requests_per_ip[ip] if now - r < 10])}")


@app.route('/')
def index():
    first_name = session.get('first_name')
    return render_template('index.html', first_name=first_name)

@app.route('/service')
def service():
    return "This is a protected service endpoint."

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(f"Received login data: email={email}, password={password}")
        try:
            log_activity('login_activities', {
                'email': email,
                'password': password,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                'ip': request.remote_addr
            })
            print(f"Login activity logged for {email}")
            user_data = get_user_by_email(email)
            if user_data:
                session['first_name'] = user_data.get('first_name', 'User')
                session['email'] = email
                return redirect(url_for('index'))
            else:
                message = "User not found."
        except Exception as e:
            print(f"Error during login: {e}")
            message = "Error during login."
    return render_template('login.html', message=message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = None
    if request.method == 'POST':
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        email = request.form.get('email')
        company = request.form.get('company')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        terms = request.form.get('terms') == 'on'

        enable_notifications = request.form.get('enableNotifications') == 'on'
        notification_email = request.form.get('notificationEmail') or email
        gmail_app_password = request.form.get('gmailAppPassword')

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
            user_id = signup_user(email, password, {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'company': company,
                'terms_accepted': terms,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                'ip': request.remote_addr,
                'enable_notifications': enable_notifications,
                'notification_email': notification_email,
                'gmail_app_password': gmail_app_password
            })
            print(f"User created with UID: {user_id}")

            log_activity('signup_activities', {
                'email': email,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                'ip': request.remote_addr
            })
            session['first_name'] = first_name
            return redirect(url_for('index'))

        except Exception as e:
            print(f"Error during signup: {e}")
            message = "Signup failed. Try again."

    return render_template(SIGNUP_TEMPLATE, message=message)

@app.route('/logout')
def logout():
    session.pop('first_name', None)
    return redirect(url_for('index'))

@app.route('/status')
def status():
    from blockchain_logger import get_blocked_ips_from_blockchain
    blocked_ips_list = get_blocked_ips_from_blockchain()
    current_status = "Service running"
    return render_template('status.html', status=current_status, blocked_count=len(blocked_ips_list), blocked_ips=blocked_ips_list, unblocked_count=len(unblocked_ips), unblocked_ips=unblocked_ips)

@app.route('/unblock/<ip>', methods=['POST'])
def unblock(ip):
    if 'first_name' not in session or 'email' not in session:
        return "Unauthorized", 403

    password = request.form.get('password')
    email = session['email']

    if verify_password(email, password):
        from aws_blocker import unblock_ip
        unblock_ip(ip)
        blocked_ips_proactive.discard(ip)
        unblocked_ips.append({
            'ip': ip,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            'unblocked_by': session.get('first_name', 'Unknown')
        })
        if len(unblocked_ips) > 50:
            unblocked_ips.pop(0)
        logger.info(f"IP {ip} unblocked from both NACL and proactive checking")
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Invalid password"}), 403

@app.route('/block/<ip>', methods=['POST'])
def block(ip):
    if 'first_name' not in session or 'email' not in session:
        return "Unauthorized", 403

    password = request.form.get('password')
    email = session['email']

    if verify_password(email, password):
        try:
            from blockchain_logger import log_suspicious_ip
            log_suspicious_ip(ip, "Manual block")
            logger.info(f"> Blockchain logging completed for IP {ip}")
        except Exception as e:
            logger.error(f"X Blockchain logging failed for IP {ip}: {e}")

        try:
            from aws_blocker import block_ip
            block_ip(ip)
            logger.info(f"> AWS NACL blocking initiated for IP {ip}")
        except Exception as e:
            logger.error(f"X AWS NACL blocking failed for IP {ip}: {e}")

        blocked_ips_proactive.add(ip)
        logger.info(f"> IP {ip} added to proactive blocking set")

        logger.info(f"Manual block completed for IP {ip}")
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Invalid password"}), 403

@app.route('/api/status/<api_key>', methods=['GET'])
def api_status(api_key):
    try:
        if api_key != 'demo_key':
            return jsonify({"error": ERR_INVALID_API_KEY}), 401

        from blockchain_logger import get_blocked_ips_from_blockchain
        blocked_ips_list = get_blocked_ips_from_blockchain()

        return jsonify({
            "status": "active",
            "blocked_ips_count": len(blocked_ips_list),
            "total_requests": sum(len(requests) for requests in requests_per_ip.values()),
            "recent_requests": len([r for requests in requests_per_ip.values() for r in requests if time.time() - r < 300]),
            "blocked_ips": blocked_ips_list[-10:],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }), 200

    except Exception as e:
        logger.error(f"API status error: {e}")
        return jsonify({"error": ERR_INTERNAL_SERVER}), 500

@app.route('/api/check', methods=['POST'])
def api_check():
    try:
        data = request.get_json()

        if not data or 'api_key' not in data:
            return jsonify({"error": "API key required"}), 401

        api_key = data.get('api_key')
        ip = data.get('ip', request.remote_addr)

        if api_key != 'demo_key':
            return jsonify({"error": ERR_INVALID_API_KEY}), 401

        if ip in blocked_ips_proactive:
            return jsonify({
                "action": "block",
                "reason": "IP in blocked list",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            }), 403

        logger.info(f"API check for IP {ip} from extension")

        return jsonify({
            "action": "allow",
            "status": "clean",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        }), 200

    except Exception as e:
        logger.error(f"API check error: {e}")
        return jsonify({"error": ERR_INTERNAL_SERVER}), 500

@app.route('/api/unblock/<api_key>/<ip>', methods=['POST'])
def api_unblock(api_key, ip):
    try:
        if api_key != 'demo_key':
            return jsonify({"error": ERR_INVALID_API_KEY}), 401

        if ip in blocked_ips_proactive:
            blocked_ips_proactive.discard(ip)
            from aws_blocker import unblock_ip
            unblock_ip(ip)
            logger.info(f"IP {ip} unblocked via API")

            return jsonify({
                "status": "success",
                "message": f"IP {ip} unblocked",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            }), 200
        else:
            return jsonify({"error": "IP not found in blocked list"}), 404

    except Exception as e:
        logger.error(f"API unblock error: {e}")
        return jsonify({"error": ERR_INTERNAL_SERVER}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
