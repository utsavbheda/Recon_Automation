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
