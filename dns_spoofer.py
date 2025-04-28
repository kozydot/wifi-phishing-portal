"""
Simple DNS spoofing server using dnslib.

Listens for DNS queries and responds with a fixed IP address (REDIRECT_IP)
for all A record requests, effectively redirecting clients to the
captive portal. Logs DNS queries using the configured logging setup.
"""
import socket
import threading
import json
import os
import sys
import logging
import logging.config
import time # Added for sleep in main loop error case
from datetime import datetime
from dnslib import DNSRecord, RR, A, QTYPE, DNSHeader, DNSQuestion

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
    # Get the DNS spoofer specific logger instance
    logger = logging.getLogger('dns_spoofer')
    logger.info("Logging configured successfully using logging_config.")
except ImportError as ie:
    # Fallback basic config if import fails
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - [FALLBACK] %(message)s')
    logger = logging.getLogger('dns_spoofer_fallback')
    logger.error(f"Failed to import logging_config: {ie}. Using basic fallback logging.")
except Exception as e:
    # Catch other potential errors during logging setup
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - [FALLBACK_ERROR] %(message)s')
    logger = logging.getLogger('dns_spoofer_error')
    logger.error(f"CRITICAL ERROR setting up logging: {e}", exc_info=True)
# --- ---

# --- Constants ---
# LISTEN_IP = '0.0.0.0' # Removed - will bind to specific redirect_ip
LISTEN_PORT = 53
CONFIG_FILENAME = 'config.json'
# LOG_DIR_NAME and DNS_LOG_FILENAME are no longer needed here as logging is centralized
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
        logger.info(f"Configuration loaded successfully from {config_path}.")
        # Avoid logging sensitive keys from config
        loggable_config = {k: v for k, v in config.items() if k not in ['fernet_key', 'wifi_password']}
        logger.debug(f"Loaded configuration (sensitive fields omitted): {json.dumps(loggable_config)}")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding configuration file {config_path}: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading configuration {config_path}: {e}", exc_info=True)
        return None

def log_dns_query(client_ip, domain, qtype_name):
    """Logs a DNS query using the configured logger."""
    # Logging is now handled by the configured handlers (console, file_json)
    logger.info(f"*** DNS Query Received *** Type: {qtype_name}, Domain: {domain}", extra={'client_ip': client_ip, 'domain': domain, 'query_type': qtype_name})

def handle_dns_request(data, addr, sock, redirect_ip):
    """
    Parses a DNS request, logs it, and sends a spoofed response
    redirecting A record queries to the specified redirect_ip.

    Args:
        data (bytes): Raw DNS request data.
        addr (tuple): Client address (ip, port).
        sock (socket.socket): The server socket.
        redirect_ip (str): The IP address to redirect A queries to.
    """
    client_ip = addr[0]
    client_port = addr[1]
    logger.debug(f"Handling request from {client_ip}:{client_port}")
    try:
        request = DNSRecord.parse(data)
        if not request.questions:
            logger.warning(f"Received DNS request with no questions", extra={'client_ip': client_ip})
            return

        # Create reply header based on request
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        # Process the first question (common case)
        q = request.q
        domain = str(q.qname).rstrip('.')
        qtype_name = QTYPE[q.qtype]

        log_dns_query(client_ip, domain, qtype_name)

        # Add spoofed A record answer ONLY for A queries
        if q.qtype == QTYPE.A:
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(redirect_ip), ttl=60))
            logger.info(f"Spoofing A record response -> {redirect_ip}", extra={'client_ip': client_ip, 'domain': domain})
        else:
            # For non-A queries, just log and send the reply without an answer section.
            # This implicitly tells the client we don't have the record type they asked for.
            # Alternatively, set rcode to NXDOMAIN if desired.
            # reply.header.rcode = RCODE.NXDOMAIN
            logger.debug(f"Ignoring non-A query ({qtype_name})", extra={'client_ip': client_ip, 'domain': domain})

        packed_reply = reply.pack()
        sock.sendto(packed_reply, addr)
        logger.debug(f"Sent {len(packed_reply)} byte reply to {client_ip}:{client_port} for {domain}")

    except Exception as e:
        logger.error(f"Error handling DNS request", extra={'client_ip': client_ip}, exc_info=True)

def start_dns_server(listen_port, redirect_ip):
    """
    Starts the DNS server, listening for requests and handling them in threads.
    Binds specifically to the redirect_ip.

    Args:
        listen_port (int): Port to listen on (usually 53).
        redirect_ip (str): IP address to bind the server to and redirect A queries to.
    """
    sock = None
    listen_ip = redirect_ip # Bind to the same IP we redirect to
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow address reuse immediately
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((listen_ip, listen_port))
        logger.info(f"DNS spoofing server started on {listen_ip}:{listen_port}, redirecting A records to {redirect_ip}")

        while True:
            try:
                # Receive data (up to 512 bytes for standard DNS UDP)
                data, addr = sock.recvfrom(512)
                logger.debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                # Handle each request in a new thread
                # Consider using a ThreadPoolExecutor for better resource management under high load
                thread = threading.Thread(target=handle_dns_request,
                                          args=(data, addr, sock, redirect_ip),
                                          daemon=True) # Daemon threads won't block exit
                thread.start()
            except OSError as e:
                # Errors during recvfrom (e.g., socket closed)
                logger.error(f"Socket error during recvfrom: {e}", exc_info=True)
                # Decide if the loop should break based on the error
                if not sock or sock.fileno() == -1: # Check if socket is closed
                     logger.info("Socket closed, stopping DNS server loop.")
                     break
            except Exception as e:
                # Catch-all for unexpected errors in the main loop
                logger.error(f"Unexpected error in DNS server loop: {e}", exc_info=True)
                # Consider adding a small delay here to prevent tight error loops
                time.sleep(0.1)

    except OSError as e:
        logger.critical(f"Failed to bind DNS server to {listen_ip}:{listen_port}: {e}. Check permissions and if port 53 is already in use.", exc_info=True)
    except Exception as e:
        logger.critical(f"Unexpected error starting DNS server: {e}", exc_info=True)
    finally:
        if sock:
            logger.info("Closing DNS server socket.")
            sock.close()

if __name__ == '__main__':
    script_dir = os.path.dirname(__file__)
    # Config path relative to this script
    config_path = os.path.join(script_dir, CONFIG_FILENAME)

    config = load_config(config_path)

    if config:
        redirect_ip = config.get('captive_portal_ip')
        if not redirect_ip:
            logger.critical("Missing 'captive_portal_ip' in configuration. Exiting.")
            sys.exit(1)

        # Log directory creation is handled by logging_config.py setup

        # Start the server, binding to the redirect_ip
        try:
            logger.info(f"Starting DNS server, binding to redirect IP: {redirect_ip}")
            start_dns_server(LISTEN_PORT, redirect_ip) # Pass only port and redirect IP
        except KeyboardInterrupt:
             logger.info("KeyboardInterrupt received. Shutting down DNS server.")
        except Exception as e:
             logger.critical(f"DNS Server failed to start or crashed unexpectedly: {e}", exc_info=True)
             sys.exit(1) # Exit if server fails critically
    else:
        logger.critical("Failed to load configuration. Exiting.")
        sys.exit(1)

    logger.info("DNS Spoofer script finished.")
