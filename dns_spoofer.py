"""
Simple DNS spoofing server.

Listens for DNS queries and responds with a fixed IP address (REDIRECT_IP)
for all A record requests, effectively redirecting clients to the
captive portal. Logs DNS queries to a file.
"""
import socket
import threading
import json
import os
import sys
import logging
from datetime import datetime
from dnslib import DNSRecord, RR, A, QTYPE, DNSHeader, DNSQuestion, QTYPE

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])
# --- ---

# --- Constants ---
LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 53
CONFIG_FILENAME = 'config.json'
LOG_DIR_NAME = 'login_details'
DNS_LOG_FILENAME = 'dns_queries.log'
# --- ---

def load_config(config_path):
    """Loads configuration from a JSON file."""
    if not os.path.exists(config_path):
        logging.error(f"Configuration file not found: {config_path}")
        return None
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        logging.info(f"Configuration loaded from {config_path}.")
        return config
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding configuration file {config_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error loading configuration {config_path}: {e}")
        return None

def log_dns_query(client_ip, domain, dns_log_file):
    """Logs a DNS query to the console and a specified file."""
    timestamp = datetime.now().isoformat()
    log_line = f"DNS query from {client_ip} for {domain}"
    logging.info(log_line) # Log to console via logging setup
    try:
        with open(dns_log_file, 'a') as f:
            f.write(f"[{timestamp}] {log_line}\n")
    except OSError as e:
        logging.error(f"Failed to write to DNS log file {dns_log_file}: {e}")

def handle_dns_request(data, addr, sock, redirect_ip, dns_log_file):
    """
    Parses a DNS request, logs it, and sends a spoofed response
    redirecting A record queries to the specified redirect_ip.

    Args:
        data (bytes): Raw DNS request data.
        addr (tuple): Client address (ip, port).
        sock (socket.socket): The server socket.
        redirect_ip (str): The IP address to redirect A queries to.
        dns_log_file (str): Path to the DNS query log file.
    """
    client_ip = addr[0]
    try:
        request = DNSRecord.parse(data)
        if not request.questions:
            logging.warning(f"Received DNS request with no questions from {client_ip}")
            return

        # Log all questions
        for q in request.questions:
            domain = str(q.qname).rstrip('.') # Ensure trailing dot is removed for logging consistency
            log_dns_query(client_ip, domain, dns_log_file)

        # Create reply
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

        # Add spoofed A record answer for A queries
        # For other query types, we could return NXDOMAIN or REFUSED,
        # but for a simple captive portal, redirecting A is often sufficient.
        q = request.q # Assuming only one question for simplicity here
        if q.qtype == QTYPE.A:
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(redirect_ip), ttl=60))
            logging.debug(f"Replying to {client_ip} for {q.qname} with A record -> {redirect_ip}")
        else:
            # Optionally handle other types, e.g., return NXDOMAIN
            logging.debug(f"Ignoring non-A query ({QTYPE[q.qtype]}) from {client_ip} for {q.qname}")
            # To explicitly refuse or indicate no record:
            # reply.header.rcode = RCODE.NXDOMAIN # Or RCODE.REFUSED
            # For simplicity, we just send the reply without an answer for non-A

        sock.sendto(reply.pack(), addr)

    except Exception as e:
        logging.error(f"Error handling DNS request from {client_ip}: {e}")

def start_dns_server(listen_ip, listen_port, redirect_ip, dns_log_file):
    """
    Starts the DNS server, listening for requests and handling them in threads.

    Args:
        listen_ip (str): IP address to listen on.
        listen_port (int): Port to listen on.
        redirect_ip (str): IP address to redirect A queries to.
        dns_log_file (str): Path to the DNS query log file.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((listen_ip, listen_port))
        logging.info(f"DNS spoofing server started on {listen_ip}:{listen_port}, redirecting A records to {redirect_ip}")
        logging.info(f"Logging DNS queries to: {dns_log_file}")

        while True:
            try:
                # Receive data (up to 512 bytes for standard DNS UDP)
                data, addr = sock.recvfrom(512)
                # Handle each request in a new thread
                # Consider using a ThreadPoolExecutor for better resource management under high load
                thread = threading.Thread(target=handle_dns_request,
                                          args=(data, addr, sock, redirect_ip, dns_log_file),
                                          daemon=True) # Daemon threads won't block exit
                thread.start()
            except OSError as e:
                # Errors during recvfrom (e.g., socket closed)
                logging.error(f"Socket error during recvfrom: {e}")
                # Decide if the loop should break based on the error
                if not sock or sock.fileno() == -1: # Check if socket is closed
                     logging.info("Socket closed, stopping DNS server loop.")
                     break
            except Exception as e:
                # Catch-all for unexpected errors in the main loop
                logging.error(f"Unexpected error in DNS server loop: {e}")
                # Consider adding a small delay here to prevent tight error loops

    except OSError as e:
        logging.error(f"Failed to bind DNS server to {listen_ip}:{listen_port}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error starting DNS server: {e}")
    finally:
        if sock:
            logging.info("Closing DNS server socket.")
            sock.close()

if __name__ == '__main__':
    script_dir = os.path.dirname(__file__)
    config_path = os.path.join(script_dir, CONFIG_FILENAME)
    log_dir = os.path.join(script_dir, LOG_DIR_NAME)

    config = load_config(config_path)

    if config:
        redirect_ip = config.get('captive_portal_ip')
        if not redirect_ip:
            logging.error("Missing 'captive_portal_ip' in configuration.")
            sys.exit(1)

        # Ensure log directory exists
        try:
            os.makedirs(log_dir, exist_ok=True)
            dns_log_path = os.path.join(log_dir, DNS_LOG_FILENAME)
            start_dns_server(LISTEN_IP, LISTEN_PORT, redirect_ip, dns_log_path)
        except OSError as e:
            logging.error(f"Could not create log directory {log_dir}: {e}")
            sys.exit(1)
        except Exception as e:
             logging.error(f"An unexpected error occurred: {e}")
             sys.exit(1)
    else:
        logging.error("Failed to load configuration. Exiting.")
        sys.exit(1)
