"""
Utility to decrypt and display captured credentials stored in an encrypted file.

Reads the Fernet encryption key from the configuration file and uses it
to decrypt the contents of the specified credential file.
"""
import os
import json
import sys
import logging
import argparse
from cryptography.fernet import Fernet, InvalidToken

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])
# --- ---

# --- Default Paths ---
DEFAULT_CONFIG_FILENAME = 'config.json'
DEFAULT_CRED_DIR_NAME = 'login_details'
DEFAULT_CRED_FILENAME = 'captured_credentials.enc'
# --- ---

def load_config(config_path):
    """Loads configuration from a JSON file."""
    if not os.path.exists(config_path):
        logging.error(f"Configuration file not found: {config_path}")
        return None
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logging.debug(f"Configuration loaded from {config_path}.")
        return config
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding configuration file {config_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error loading configuration {config_path}: {e}")
        return None

def get_fernet_key(config):
    """
    Retrieves the Fernet key from the configuration.

    SECURITY WARNING: Storing the encryption key directly in a plain JSON
    configuration file is insecure. Consider using environment variables,
    a dedicated secrets management system, or prompting the user for the key.
    """
    if not config:
        return None
    try:
        key = config['fernet_key']
        logging.warning("SECURITY WARNING: Loading Fernet key from config file. This is insecure for production environments.")
        return key.encode() # Fernet key must be bytes
    except KeyError:
        logging.error("Configuration file is missing the 'fernet_key'.")
        return None
    except Exception as e:
        logging.error(f"Unexpected error retrieving Fernet key: {e}")
        return None

def decrypt_and_display(cred_file_path, fernet_instance):
    """
    Reads an encrypted file line by line, decrypts each line,
    and displays the JSON data contained within.

    Args:
        cred_file_path (str): Path to the encrypted credential file.
        fernet_instance (Fernet): Initialized Fernet instance for decryption.
    """
    if not os.path.exists(cred_file_path):
        logging.error(f"Credentials file not found: {cred_file_path}")
        return

    logging.info(f"Attempting to decode credentials from: {cred_file_path}\n")
    lines_processed = 0
    lines_failed = 0

    try:
        with open(cred_file_path, 'rb') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                lines_processed += 1
                try:
                    decrypted_bytes = fernet_instance.decrypt(line)
                    data = json.loads(decrypted_bytes.decode('utf-8'))

                    # Basic display - enhance as needed
                    print(f"--- Record {lines_processed} ---")
                    print(f"  Time:      {data.get('timestamp', 'N/A')}")
                    print(f"  Provider:  {data.get('provider', 'N/A')}")
                    print(f"  Client IP: {data.get('client_ip', 'N/A')}")
                    print(f"  User Agent:{data.get('user_agent', 'N/A')}")
                    print(f"  Username:  {data.get('username', 'N/A')}")
                    # WARNING: Displaying passwords, even decoded ones, is risky.
                    # Consider masking or omitting in a real application.
                    print(f"  Password:  {data.get('password', 'N/A')}")
                    print("-" * 40)

                except InvalidToken:
                    logging.error(f"Failed to decrypt line {i+1}: Invalid token or key.")
                    lines_failed += 1
                except json.JSONDecodeError:
                    logging.error(f"Failed to decode JSON on line {i+1} after decryption.")
                    lines_failed += 1
                except UnicodeDecodeError:
                     logging.error(f"Failed to decode bytes to UTF-8 on line {i+1} after decryption.")
                     lines_failed += 1
                except Exception as e:
                    logging.error(f"Failed to process line {i+1}: {e}")
                    lines_failed += 1

    except FileNotFoundError: # Should be caught by os.path.exists, but defensive
        logging.error(f"Credentials file disappeared during processing: {cred_file_path}")
        return
    except OSError as e:
        logging.error(f"Error reading credentials file {cred_file_path}: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred during file processing: {e}")
        return

    logging.info(f"\nFinished processing. Records processed: {lines_processed}, Failures: {lines_failed}")


def main():
    """Main function to parse arguments, load key, and decrypt file."""
    script_dir = os.path.dirname(__file__)

    parser = argparse.ArgumentParser(description="Decrypt and display captured credentials.")
    parser.add_argument(
        '-c', '--config',
        default=os.path.join(script_dir, DEFAULT_CONFIG_FILENAME),
        help=f"Path to the configuration file (default: {DEFAULT_CONFIG_FILENAME})"
    )
    parser.add_argument(
        '-f', '--file',
        default=os.path.join(script_dir, DEFAULT_CRED_DIR_NAME, DEFAULT_CRED_FILENAME),
        help=f"Path to the encrypted credential file (default: {os.path.join(DEFAULT_CRED_DIR_NAME, DEFAULT_CRED_FILENAME)})"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    if not config:
        sys.exit(1)

    key = get_fernet_key(config)
    if not key:
        sys.exit(1)

    try:
        fernet_instance = Fernet(key)
    except Exception as e:
        logging.error(f"Failed to initialize Fernet instance with the provided key: {e}")
        sys.exit(1)

    decrypt_and_display(args.file, fernet_instance)


if __name__ == '__main__':
    main()
