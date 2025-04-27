# WiFi Phishing Portal

A phishing portal framework designed to simulate popular login pages (Facebook, Twitter, Google) for **educational, research, and authorized penetration testing** purposes only.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Setup Instructions](#setup-instructions)
- [Running the Portal](#running-the-portal)
- [Credential Capture & Storage](#credential-capture--storage)
- [Customizing Templates](#customizing-templates)
- [Security Considerations](#security-considerations)
- [Legal Disclaimer](#legal-disclaimer)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

This project provides a phishing portal that mimics the login pages of major providers. It is intended to demonstrate social engineering techniques, test user awareness, and evaluate network security controls in a controlled environment.

**Do not use this tool for unauthorized activities.**

---

## Features

- **Realistic cloned login pages:**
  - Facebook
  - Twitter (X)
  - Google
- **Responsive design:** Works on desktop and mobile devices.
- **Credential capture:** Stores submitted usernames and passwords.
- **Encrypted storage:** Credentials saved in encrypted format.
- **Logging:** Tracks login attempts and DNS queries.
- **DNS spoofing support:** Redirects victims transparently.
- **Easy customization:** Modify or add new provider templates.
- **Modular codebase:** Refactored Python scripts for portal, spoofing, decoding, and orchestration.
- **Improved Logging:** Uses standard Python logging.
- **Modernized UI:** Improved styling and layout for the provider selection page using dedicated CSS and embedded SVG logos.
- **Modular codebase:** Refactored Python scripts for portal, spoofing, decoding, and orchestration.
- **Improved Logging:** Uses standard Python logging.

---

## Setup Instructions

### 1. Environment

- **Python 3.7+** recommended.
- Tested on Linux and Windows.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configuration

- Edit `config.json` in the project root directory. Key settings:
  - `"ssid"`: The name for the fake Wi-Fi network (if using `main.py`'s AP feature on Windows).
  - `"wifi_password"`: Password for the fake Wi-Fi (leave empty for open network).
  - `"captive_portal_ip"`: **Crucial!** This **must** be the IP address of the computer running the portal script *on the network interface that connected clients will use*. For example, if using Windows Mobile Hotspot, this is often `192.168.137.1`. Incorrect configuration will prevent redirection.
  - `"fernet_key"`: A 32-byte URL-safe base64 encoded key for encrypting credentials. See [Generating Your Own Fernet Key](#generating-your-own-fernet-key).
- Edit `config.json` in the project root directory. Key settings:
  - `"ssid"`: The name for the fake Wi-Fi network (if using `main.py`'s AP feature on Windows).
  - `"wifi_password"`: Password for the fake Wi-Fi (leave empty for open network).
  - `"captive_portal_ip"`: **Crucial!** This **must** be the IP address of the computer running the portal script *on the network interface that connected clients will use*. For example, if using Windows Mobile Hotspot, this is often `192.168.137.1`. Incorrect configuration will prevent redirection.
  - `"fernet_key"`: A 32-byte URL-safe base64 encoded key for encrypting credentials. See [Generating Your Own Fernet Key](#generating-your-own-fernet-key).

### 4. Network setup

You have multiple options to deploy the phishing portal over WiFi:

#### Option 1: Using `main.py` (Recommended)
#### Option 1: Using `main.py` (Recommended)

- The `main.py` script orchestrates the DNS spoofer (`dns_spoofer.py`) and the captive portal (`portal/app.py`).
- It can optionally attempt to create a Wi-Fi Hosted Network on **Windows** using `netsh` (requires administrator privileges). This feature is commented out by default in `main.py`.
- **Configuration:** Ensure `captive_portal_ip` in `config.json` is set correctly for your network setup (see [Configuration](#3-configuration)).
- **Running:** Execute `python main.py` (may require administrator/root privileges for DNS/Web server ports).
- The `main.py` script orchestrates the DNS spoofer (`dns_spoofer.py`) and the captive portal (`portal/app.py`).
- It can optionally attempt to create a Wi-Fi Hosted Network on **Windows** using `netsh` (requires administrator privileges). This feature is commented out by default in `main.py`.
- **Configuration:** Ensure `captive_portal_ip` in `config.json` is set correctly for your network setup (see [Configuration](#3-configuration)).
- **Running:** Execute `python main.py` (may require administrator/root privileges for DNS/Web server ports).

#### Option 2: Manual Component Execution (Advanced/Debugging)
#### Option 2: Manual Component Execution (Advanced/Debugging)

- You can run the components separately if needed, but `main.py` handles the coordination.
- **DNS Spoofer:** `python dns_spoofer.py` (requires root/admin). Reads `config.json` for redirection IP.
- **Captive Portal:** `python portal/app.py` (requires root/admin if using port 80). Reads `config.json` for Fernet key.
- You would need to manage the network setup (hotspot, DNS settings on clients/DHCP) manually if not using `main.py`.
- You can run the components separately if needed, but `main.py` handles the coordination.
- **DNS Spoofer:** `python dns_spoofer.py` (requires root/admin). Reads `config.json` for redirection IP.
- **Captive Portal:** `python portal/app.py` (requires root/admin if using port 80). Reads `config.json` for Fernet key.
- You would need to manage the network setup (hotspot, DNS settings on clients/DHCP) manually if not using `main.py`.

- Ensure firewall rules allow inbound HTTP traffic.

---

## Running the Portal (Using `main.py`)
## Running the Portal (Using `main.py`)

### 1. Configure `config.json`

- Ensure `captive_portal_ip` and `fernet_key` are set correctly. See [Configuration](#3-configuration).

### 2. Run `main.py`
### 1. Configure `config.json`

- Ensure `captive_portal_ip` and `fernet_key` are set correctly. See [Configuration](#3-configuration).

### 2. Run `main.py`

```bash
# May require administrator/root privileges!
python main.py
# May require administrator/root privileges!
python main.py
```

- This command starts:
  - The DNS spoofing server (listening on UDP port 53).
  - The captive portal web server (listening on TCP port 80).
  - A monitor that logs when new credentials are saved.
- (Optional) If uncommented in `main.py`, it also attempts to start a Wi-Fi hotspot on Windows.

### 3. Connect Client Device

- Connect a client device (e.g., phone) to the Wi-Fi network being served or targeted by the DNS spoofer.
- This command starts:
  - The DNS spoofing server (listening on UDP port 53).
  - The captive portal web server (listening on TCP port 80).
  - A monitor that logs when new credentials are saved.
- (Optional) If uncommented in `main.py`, it also attempts to start a Wi-Fi hotspot on Windows.

### 3. Connect Client Device

- Connect a client device (e.g., phone) to the Wi-Fi network being served or targeted by the DNS spoofer.

### 4. Trigger Redirection

- On the client device, open a web browser and try to navigate to any non-HTTPS website (e.g., `http://example.com`).
- The DNS spoofer should redirect the request to the captive portal IP (`captive_portal_ip` from `config.json`).
- The captive portal (`portal/app.py`) should serve the provider selection page.
### 4. Trigger Redirection

- On the client device, open a web browser and try to navigate to any non-HTTPS website (e.g., `http://example.com`).
- The DNS spoofer should redirect the request to the captive portal IP (`captive_portal_ip` from `config.json`).
- The captive portal (`portal/app.py`) should serve the provider selection page.

### 5. Submit Credentials

- Navigate through the portal pages and submit credentials on a fake login page.
- The portal will encrypt and save the credentials.
- The `main.py` script running in the terminal will log that credentials have been captured.
### 5. Submit Credentials

- Navigate through the portal pages and submit credentials on a fake login page.
- The portal will encrypt and save the credentials.
- The `main.py` script running in the terminal will log that credentials have been captured.

---

## Credential Capture & Storage

- **Encrypted Credentials:** Saved line-by-line in `login_details/captured_credentials.enc`.
- **Encrypted Credentials:** Saved line-by-line in `login_details/captured_credentials.enc`.
- **Logs:**
  - **DNS Queries:** `login_details/dns_queries.log` logs requests handled by `dns_spoofer.py`.
  - **Portal Activity:** The captive portal (`portal/app.py`) logs activity (visits, submissions, errors) to standard output/error when run via `main.py`. Check the terminal output of `main.py`.
  - **Main Orchestrator:** `main.py` logs its own status (startup, errors, credential capture detection) to standard output/error.
  - **DNS Queries:** `login_details/dns_queries.log` logs requests handled by `dns_spoofer.py`.
  - **Portal Activity:** The captive portal (`portal/app.py`) logs activity (visits, submissions, errors) to standard output/error when run via `main.py`. Check the terminal output of `main.py`.
  - **Main Orchestrator:** `main.py` logs its own status (startup, errors, credential capture detection) to standard output/error.

### Generating Your Own Fernet Key

The portal uses **Fernet symmetric encryption** (from the `cryptography` library) to securely store captured credentials.

To generate your own Fernet key:

1. Open a Python shell or script and run:

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())
```

This will output a base64-encoded key string, e.g.:

```
b'k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2='
```

2. Copy the key **without the `b'...'` and quotes**:

```
k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2k3x2k1k2=
```

3. Open `config.json` and set:
3. Open `config.json` and set:

```json
{
  "fernet_key": "your-generated-key-here",
  ...
}
```

4. Restart the phishing portal to use the new key.

### Decoding credentials with your key

Use the provided script:

```bash
python decode_credentials.py
python decode_credentials.py
```

- The script reads the encrypted credentials file.
- It uses the Fernet key from `config.json` to decrypt.
- Outputs plaintext usernames and passwords.

**Note:** You must use the **same Fernet key** that was used during credential capture to successfully decrypt.

---

## Customizing Templates

- Located in `portal/templates/`.
- Located in `portal/templates/`.
- Files:
  - `login_facebook.html`
  - `login_twitter.html`
  - `login_google.html`
  - `select_provider.html` (provider selection page)
- **Edit HTML** (`portal/templates/*.html`) and **CSS** (`portal/static/css/select_provider.css`) to change appearance. Logos are embedded as data URIs in `select_provider.html`.
- **Add new providers:**
  - Create a new HTML template.
  - Add routing logic in `app.py`.
  - Update `select_provider.html` to include the new option.

---

## Security Considerations

- **Use in isolated, controlled environments only.**
- **Never target real users without explicit permission.**
- **Test on your own devices or authorized test groups.**
- **Disable internet access for test victims to avoid real data leaks.**
- **Encrypt all captured data.**

---

## Legal Disclaimer

This tool is intended **solely for educational purposes, authorized penetration testing, and security research**. Unauthorized use against systems or individuals without explicit consent is **illegal and unethical**.

The author **assume no liability** for misuse or damages caused by this tool.

---

## Troubleshooting

- **DNS spoofing not working:** Requires root/admin; verify network interface and rules.
- **Credentials not decrypting:** Ensure correct encryption key is configured.
- **Broken layout on mobile:** Adjust CSS in templates.

---

## License

For educational and authorized testing use only. No warranty or support provided.

---

## Credits

Developed by kozydot.

Inspired by open-source phishing frameworks and educational tools.
