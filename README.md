# WiFi Phishing Portal

A phishing portal framework designed to simulate popular login pages (Facebook, Twitter, Google) for **educational, research, and authorized penetration testing** purposes only.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Setup Instructions](#setup-instructions)
- [Running the Portal](#running-the-portal)
- [Logging System](#logging-system)
- [Credential Capture & Storage](#credential-capture--storage)
- [Customizing Templates](#customizing-templates)
- [Security Considerations](#security-considerations)
- [Legal Disclaimer](#legal-disclaimer)
- [Recent Updates](#recent-updates)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Credits](#credits)

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
- **Encrypted storage:** Credentials saved in encrypted format using Fernet.
- **Structured Logging:** Comprehensive logging across all components (details below).
- **DNS spoofing support:** Redirects victims transparently.
- **Easy customization:** Modify or add new provider templates.
- **Modular codebase:** Refactored Python scripts for portal, spoofing, decoding, and orchestration.
- **Modernized UI:** Improved styling and layout for the provider selection page using dedicated CSS and embedded SVG logos.

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

### 4. Network setup

You have multiple options to deploy the phishing portal over WiFi:

#### Option 1: Using `main.py` (Recommended)

- The `main.py` script orchestrates the DNS spoofer (`dns_spoofer.py`) and the captive portal (`portal/app.py`).
- It can optionally attempt to create a Wi-Fi Hosted Network on **Windows** using `netsh` (requires administrator privileges). This feature is commented out by default in `main.py`.
- **Configuration:** Ensure `captive_portal_ip` in `config.json` is set correctly for your network setup (see [Configuration](#3-configuration)).
- **Running:** Execute `python main.py` (may require administrator/root privileges for DNS/Web server ports).

#### Option 2: Manual Component Execution (Advanced/Debugging)

- You can run the components separately if needed, but `main.py` handles the coordination.
- **DNS Spoofer:** `python dns_spoofer.py` (requires root/admin). Reads `config.json` for redirection IP.
- **Captive Portal:** `python portal/app.py` (requires root/admin if using port 80). Reads `config.json` for Fernet key.
- You would need to manage the network setup (hotspot, DNS settings on clients/DHCP) manually if not using `main.py`.

- Ensure firewall rules allow inbound HTTP/DNS traffic as needed.

---

## Running the Portal (Using `main.py`)

### 1. Configure `config.json`

- Ensure `captive_portal_ip` and `fernet_key` are set correctly. See [Configuration](#3-configuration).

### 2. Run `main.py`

```bash
# May require administrator/root privileges!
python main.py
```

- This command starts:
  - The DNS spoofing server (listening on UDP port 53).
  - The captive portal web server (listening on TCP port 80).
  - A monitor that logs when new credentials are saved.
- (Optional) If uncommented in `main.py`, it also attempts to start a Wi-Fi hotspot on Windows.
- Check the console output for detailed logs.

### 3. Connect Client Device

- Connect a client device (e.g., phone) to the Wi-Fi network being served or targeted by the DNS spoofer.

### 4. Trigger Redirection

- On the client device, open a web browser and try to navigate to any non-HTTPS website (e.g., `http://example.com`).
- The DNS spoofer should redirect the request to the captive portal IP (`captive_portal_ip` from `config.json`).
- The captive portal (`portal/app.py`) should serve the provider selection page.

### 5. Submit Credentials

- Navigate through the portal pages and submit credentials on a fake login page.
- The portal will encrypt and save the credentials.
- Check the console output and the log file (`logs/wifi_portal.log`) for confirmation and details.

---

## Logging System

The application now uses a comprehensive, structured logging system configured via `logging_config.py`.

- **Configuration:** `wifi-phishing-portal/logging_config.py` defines formatters, handlers, and loggers.
- **Console Output:** Provides readable, timestamped logs to the standard output during execution. Log level is generally INFO, but can be configured. **INFO level names are colored green** for better visibility (requires `colorlog` library).
- **File Output:**
    - **Location:** `wifi-phishing-portal/logs/wifi_portal.log`
    - **Format:** JSON (structured logs), making it easy to parse and analyze.
    - **Rotation:** The log file rotates automatically when it reaches 10MB, keeping up to 5 backup files.
- **Key Logged Events:**
    - Application startup and shutdown (main orchestrator, DNS spoofer, portal).
    - Configuration loading (success, errors, file paths).
    - DNS requests received and responses sent (including client IP, domain, query type).
    - Captive portal requests (start/end, method, path, status code, duration, client IP, user agent, request ID).
    - Credential submission attempts (including provider, client IP, username - **passwords are masked**).
    - Credential encryption and saving (success/errors).
    - Credential decryption process (using `decode_credentials.py`).
    - Errors and warnings across all components, often with tracebacks (`exc_info`).
- **Loggers:** Different components use specific loggers (`wifi_portal`, `dns_spoofer`, `credential_decoder`, `werkzeug`) allowing for potential fine-grained filtering if needed.

---

## Credential Capture & Storage

- **Encrypted Credentials:** Saved line-by-line in `wifi-phishing-portal/login_details/captured_credentials.enc`. Each line contains encrypted JSON data.
- **Logs:** All operational logs (DNS activity, portal requests, errors, credential capture events) are now centralized in `wifi-phishing-portal/logs/wifi_portal.log` (JSON format) and also mirrored to the console. The old `dns_queries.log` is no longer used.

### Generating Your Own Fernet Key

The portal uses **Fernet symmetric encryption** (from the `cryptography` library) to securely store captured credentials.

To generate your own Fernet key:

1. Open a Python shell or script and run:

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())
```

This will output a base64-encoded key string.

2. Copy the key **without the `b'...'` and quotes**.

3. Open `config.json` and set the value for `"fernet_key"`.

4. Restart the phishing portal to use the new key.

### Decoding credentials with your key

Use the provided script:

```bash
python decode_credentials.py
```

- The script reads the encrypted credentials file (`login_details/captured_credentials.enc` by default).
- It uses the Fernet key from `config.json` to decrypt.
- Outputs decoded credential details to the console/log file.

**Note:** You must use the **same Fernet key** that was used during credential capture to successfully decrypt.

---

## Customizing Templates

- Located in `portal/templates/`.
- Files:
  - `login_facebook.html`
  - `login_twitter.html`
  - `login_google.html`
  - `select_provider.html` (provider selection page)
- **Edit HTML** (`portal/templates/*.html`) and **CSS** (`portal/static/css/select_provider.css`) to change appearance. Logos are embedded as data URIs in `select_provider.html`.
- **Add new providers:**
  - Create a new HTML template.
  - Add the provider key and template filename to the `TEMPLATE_MAP` in `portal/app.py`.
  - Add routing logic in `portal/app.py` if needed (or use the generic `/login/<provider>` and `/submit/<provider>` routes).
  - Update `select_provider.html` to include the new option.

---

## Security Considerations

- **Use in isolated, controlled environments only.**
- **Never target real users without explicit permission.**
- **Test on your own devices or authorized test groups.**
- **Disable internet access for test victims to avoid real data leaks.**
- **Securely manage your Fernet key.** Do not commit it to public repositories. Consider environment variables or other secure storage methods for production-like scenarios.
- **Review logs regularly**, but be mindful that even masked logs contain sensitive metadata.

---

## Legal Disclaimer

This tool is intended **solely for educational purposes, authorized penetration testing, and security research**. Unauthorized use against systems or individuals without explicit consent is **illegal and unethical**.

The author **assume no liability** for misuse or damages caused by this tool.

---

## Recent Updates (April 2025)

- **Enhanced Logging:** Implemented structured logging system using Python's `logging` module and a central configuration (`logging_config.py`). Logs are now in JSON format in `logs/wifi_portal.log` with rotation, and also mirrored to the console.
- **Colored Console Logs:** Added optional colored output for console logs (INFO level name is green) using the `colorlog` library (added to `requirements.txt`).
- **Improved Facebook Template:** Significantly updated `login_facebook.html` to more closely resemble the actual Facebook login page, including layout, styling, and embedded logo.
- **Mobile Responsiveness:** Improved layout and styling for mobile devices across all login templates (`login_facebook.html`, `login_google.html`, `login_twitter.html`).
- **Basic Email Validation:** Added `type="email"` to relevant input fields in HTML and a basic server-side check for "@" in `portal/app.py` (logged).
- **UI Enhancements:**
    - Added CSS hover animation (scale effect) to provider buttons on `select_provider.html`.
    - Fixed various minor CSS inconsistencies and styling issues.
- **Code Refinements:** General code cleanup, improved error handling visibility, and fixed subprocess execution paths.

---

## Troubleshooting

- **DNS spoofing not working:** Requires root/admin; verify network interface, firewall rules, and ensure no other service is using UDP port 53. Check logs for binding errors.
- **Portal not accessible:** Check firewall rules for TCP port 80 (or configured port). Verify `captive_portal_ip` in `config.json`. Check logs for binding errors.
- **Credentials not decrypting:** Ensure the correct Fernet key (the one used for encryption) is present in `config.json` when running `decode_credentials.py`. Check logs for decryption errors.
- **Broken layout on mobile:** Adjust CSS in templates (`portal/templates/*.html`, `portal/static/css/*.css`).
- **Check Logs:** The `logs/wifi_portal.log` file and console output are the primary sources for diagnosing issues.

---

## License

For educational and authorized testing use only. No warranty or support provided.

---

## Credits

Developed by kozydot.

Inspired by open-source phishing frameworks and educational tools.
