# Advanced Bug Bounty Reconnaissance & XSS Scanner

## 📌 Overview

This repository contains a powerful **Python-based script** designed for comprehensive reconnaissance in bug bounty hunting and penetration testing. It automates various information gathering techniques—from passive DNS enumeration to active port scanning and directory fuzzing. Additionally, it integrates a secondary script for basic **Cross-Site Scripting (XSS)** vulnerability scanning, leveraging the reconnaissance findings.

> ⚠️ **Disclaimer:** This tool is for educational purposes only. Use it strictly on systems you have explicit, written permission to test. Unauthorised scanning is illegal and unethical. The developer is not responsible for any misuse or damage caused by this tool.

---

## 🚀 Features

### 🔍 Main Script (`recon_xss.py`) Capabilities:

#### 🕵️‍♂️ Passive Reconnaissance (Scripted):
- WHOIS information lookup
- DNS record enumeration (A, AAAA, MX, TXT, NS, SOA, PTR, SRV, CNAME)
- HTTP header analysis (including security headers)

#### 🚨 Active Reconnaissance (Scripted):
- Multi-threaded TCP port scanning
- Multi-threaded directory & file discovery using wordlists

#### 🧰 Passive Reconnaissance (External Tools):
- WHOIS & `dig` integrations
- Subdomain enumeration (`subfinder`, `assetfinder`, `amass`)
- Live host identification using `httpx`
- Wayback Machine URLs using `waybackurls`

#### 🔨 Active Reconnaissance (External Tools):
- Port scanning with `naabu` and `nmap`
- Directory fuzzing with `ffuf`
- Vulnerability scanning with `nikto` and `nuclei`

#### ⚙️ Configurable:
- JSON configuration file support for custom ports, wordlists, and thread counts

#### 📑 Logging & Reporting:
- Saves all outputs and summary report in a structured directory

---

### ⚔️ Secondary Script (`xss_scanner_script.py`) Capabilities:

- **Uses recon data**: Automatically leverages `live.txt` and `wayback.txt`
- **Reflected XSS**: Scans URL query parameters & form input fields
- **Stored XSS (Conceptual)**: Attempts injection into "storable" fields (e.g., comments)
- **Basic crawler**: To expand surface for XSS testing
- **Output**: Saves to `xss_findings.txt` in recon output directory

---

## 📦 Prerequisites

### 🐍 Python 3 Libraries:

Install using pip:

```bash
pip install requests beautifulsoup4 python-whois dnspython termcolor
```

- **requests:** For making HTTP requests.
- **beautifulsoup4:** For parsing HTML.
- **python-whois:** For WHOIS lookups.
- **dnspython:** For DNS record lookups.
- **termcolor:** For colored terminal output.

## External Tools (Recommended for Full Functionality):

These tools should be installed and accessible in your system's PATH. The script will check for their presence and skip steps if they are not found.

### Subdomain Enumeration:
- subfinder
- assetfinder
- amass

### Live Host Identification:
- httpx

### Port Scanning:
- naabu
- nmap

###Directory Fuzzing:
- ffuf
- Vulnerability Scanning:
- nikto
- nuclei

###Web Archive Analysis:
- waybackurls

### System Utilities (usually pre-installed on Linux/macOS):
- Whois (command-line tool)
- dig
- sort
- grep
- cat

Installation Guides for External Tools:
Most of these tools can be installed via go get (if you have Go installed) or by downloading pre-compiled binaries from their respective GitHub repositories. For Kali Linux or similar distributions, many are available via apt install.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

> (Replace your-username and your-repo-name with your actual GitHub details)

2. Install Python dependencies:

```bash
pip install -r requirements.txt # (If you create a requirements.txt, otherwise use the command above)
```

To create a requirements.txt file with the listed dependencies:

```bash
pip freeze > requirements.txt
```

3. Ensure external tools are installed and in your PATH.

## Usage

### Running the Main Reconnaissance Script

The primary script is recon_xss.py.
```bash
python3 recon_xss.py -t <TARGET_URL> [OPTIONS]
```

## Arguments:

```bash
-t, --target (Required): The target URL (e.g., https://example.com). Must include http:// or https://.
```
```bash
-o, --output (Optional): Custom output directory name. Default is recon_<domain>_<timestamp>.
```
```bash
--no-active (Optional): Skip all active reconnaissance steps (port scan, directory bruteforce, external active tools like Nmap, FFUF, Nikto, Nuclei).
```
```bash
--config (Optional): Path to a JSON configuration file for custom settings (see config_example.json below).
```
```bash
--skip-tool-check (Optional): Skip checking if external tools are installed.
```
```bash
--xss-script (Optional): Path to the secondary XSS scanning script (xss_scanner_script.py) to run after recon completes.
```
### Example Command (Full Recon + XSS Scan):

```bash
python3 recon_xss.py -t https://example.com --xss-script ./xss_scanner_script.py
```

### Example Command (Passive Recon Only):

```bash
python3 recon_xss.py -t https://example.com --no-active
```

### Example config.json (Optional)

```bash
You can create a config.json file to customise settings:
{
    "ports": [80, 443, 8000, 8080],
    "directory_wordlists": [
        "/usr/share/wordlists/dirb/common.txt",
        "./custom_wordlists/my_dirs.txt"
    ],
    "active_threads": {
        "port_scan": 100,
        "directory_discovery": 200
    },
    "external_tools": ["subfinder", "httpx", "nuclei"]
}
```

Then run the script with:

```bash
python3 recon_xss.py -t https://example.com --config ./config.json --xss-script ./xss_scanner_script.py
```

## Output
All reconnaissance findings, logs, and the XSS scan report will be saved in a dedicated output directory (e.g., recon_example.com_2025-07-18_16-00/).

Key output files include:
- recon.log: Detailed script execution logs.
- summary_report.md: A Markdown-formatted summary of key reconnaissance findings.
- subdomains.txt: Unique subdomains found.
- live.txt: Live hosts identified from subdomains.
- wayback.txt: All URLs from Wayback Machine.
- interesting.txt: Filtered interesting URLs from Wayback Machine.
- xss_findings.txt: Report of potential XSS vulnerabilities found by xss_scanner_script.py.
- Other files for specific tool outputs (e.g., nikto_*.txt, nuclei.txt, nmap.txt, ffuf_*.html).

## XSS Scanning Details and Limitations
The xss_scanner_script.py attempts to identify:

- **Reflected XSS:** Where user input is immediately returned by the web application in an unsafe way.
- **Stored XSS:** Where malicious input is saved by the web application and later retrieved and executed by other users. The script attempts injection, but full verification of stored XSS often requires manual steps to visit pages where the data is rendered.
- **DOM-based XSS (Conceptual):** This type of XSS occurs purely on the client-side via JavaScript manipulation of the Document Object Model. This script, being requests-based, cannot execute JavaScript. Therefore, its detection for DOM-based XSS is limited to identifying reflection patterns in the raw HTML source, and a headless browser (like Selenium or Playwright) would be required for comprehensive DOM-based XSS testing.

> **Important Note:** This XSS scanner is a basic implementation for educational purposes. It may not bypass sophisticated Web Application Firewalls (WAFs) or detect all types of XSS. For robust XSS testing, consider using dedicated tools like XSStrike, OWASP ZAP, or Burp Suite.

## Contributing
Contributions are welcome! If you have suggestions for improvements, bug fixes, or new features, please feel free to:
1. Fork the repository.
2. Create a new branch (git checkout -b feature/your-feature-name).
3. Make your changes.
4. Commit your changes (git commit -m 'Add new feature').
5. Push to the branch (git push origin feature/your-feature-name).
6. Open a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
