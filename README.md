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
- **Modular codebase:** Python scripts for portal, spoofing, and decoding.

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

- Edit `wifi_phish/config.json` to customize settings such as encryption keys, server IP, or provider options.

### 4. Network setup

- Set up a WiFi hotspot or rogue access point.
- Use **DNS spoofing** (`dns_spoofer.py`) to redirect login domains (e.g., facebook.com) to your phishing server IP.
- Ensure firewall rules allow inbound HTTP traffic.

---

## Running the Portal

### 1. Start the phishing web server

```bash
python wifi_phish/portal/app.py
```

- Default port is 80 (http://localhost:80).
- Can be changed in `app.py`.

### 2. Launch DNS spoofing (optional)

```bash
python wifi_phish/dns_spoofer.py
```

- Spoofs DNS requests to redirect target domains to your server.
- Requires root/admin privileges.

### 3. Victim connects to WiFi and visits a login page

- They will be transparently redirected to the phishing portal.
- Selects a provider or is auto-redirected.

### 4. Credentials are submitted

- Data is encrypted and saved.
- Logs are updated.

---

## Credential Capture & Storage

- **Encrypted credentials:** Saved in `login_details/captured_credentials.enc`.
- **Logs:**
  - `login_details/activity.log` — login attempts.
  - `login_details/dns_queries.log` — spoofed DNS requests.

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

3. Open `wifi_phish/config.json` and set:

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
python wifi_phish/decode_credentials.py
```

- The script reads the encrypted credentials file.
- It uses the Fernet key from `config.json` to decrypt.
- Outputs plaintext usernames and passwords.

**Note:** You must use the **same Fernet key** that was used during credential capture to successfully decrypt.

---

## Customizing Templates

- Located in `wifi_phish/portal/templates/`.
- Files:
  - `login_facebook.html`
  - `login_twitter.html`
  - `login_google.html`
  - `select_provider.html` (provider selection page)
- **Edit HTML/CSS** to change appearance.
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

- **Images not loading:** Some provider logos may be blocked; replace with inline SVGs.
- **Server not accessible:** Check firewall, IP bindings, and network setup.
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
