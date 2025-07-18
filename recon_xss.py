#!/usr/bin/env python3

"""
Advanced Bug Bounty Reconnaissance Script
Version: 4.0 (Enhanced, Resilient, and Configurable)
Author: Gemini
Merged and Enhanced by ChatGPT & Gemini (with additional improvements)
Disclaimer: For educational use only. Run on systems you have explicit permission to test.
"""

import os
import subprocess
import requests
import socket
import dns.resolver
import whois
import sys
import argparse
import json
import logging
import time
from datetime import datetime
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor

# === Configuration and Setup ===

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()]) # Default to stream handler, file handler added later

# === UI Helpers ===

def print_banner():
    # Using a raw string (r"""...""") to prevent invalid escape sequence warnings
    banner = r"""
    ____             __      __                     _      ____
   / __ )____ ______/ /__   / /___  ____ _____     ( )_   / __/___  _________ ___
  / __  / __ `/ ___/ //_/  / / __ \/ __ `/ __ \   / /| | / /_/ __ \/ ___/ __ `__ \
 / /_/ / /_/ / /__/ ,<    / / /_/ / /_/ / / / /  / / | |/ __/ /_/ / /  / / / / / /
/_____/\__,/\___/_/|_|  /_/\____/\__,_/_/ /_/  /_/  |_/_/  \____/_/  /_/ /_/ /_/\
                         Reconnaissance Scanner
    """
    print(colored(banner, 'cyan'))

def print_section_header(title):
    print(colored(f"\n{'='*20} {title.upper()} {'='*20}", 'yellow'))
    logging.info(f"--- SECTION: {title.upper()} ---")

def print_info(key, value):
    log_message = f"{key}: {value}"
    logging.info(log_message)
    print(f"{colored(key, 'green'):>20}: {value}")

def print_error(message):
    logging.error(f"[!] ERROR: {message}")
    print(colored(f"[!] ERROR: {message}", 'red'))

def print_success(message):
    logging.info(f"[+] SUCCESS: {message}")
    print(colored(f"[+] SUCCESS: {message}", 'blue'))

def run_cmd(command, output_file=None):
    print(colored(f"[+] Running: {command}", "blue"))
    logging.info(f"Executing command: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        if output_file:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            logging.info(f"Command output saved to {output_file}")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {command}\nSTDOUT: {e.stdout}\nSTDERR: {e.stderr}")
        logging.error(f"Command failed: {command}. Error: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print_error(f"Command not found: {command.split(' ')[0]}. Is the tool installed and in your PATH?")
        logging.error(f"Command not found: {command.split(' ')[0]}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred running command '{command}': {e}")
        logging.error(f"Unexpected error running command '{command}': {e}")
        return None

def check_tool_installed(tool_name):
    """Checks if a given tool is in the system's PATH."""
    try:
        subprocess.run(["which", tool_name], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False # 'which' command itself might not be found on some systems

# === Recon Modules ===

def get_whois_info(domain):
    print_section_header("WHOIS Info")
    try:
        w = whois.whois(domain)
        if not w:
            print_info("WHOIS", "No WHOIS data found or domain does not exist.")
            logging.warning(f"No WHOIS data found for {domain}")
            return

        found_info = False
        for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails', 'status', 'org', 'city', 'state', 'country']:
            value = getattr(w, key, None)
            if value:
                # Handle lists returned by whois for some fields
                if isinstance(value, list):
                    value = ", ".join(map(str, value))
                print_info(key.replace("_", " ").title(), value)
                found_info = True
        if not found_info:
            print_info("WHOIS", "No significant WHOIS details extracted.")
            logging.info(f"No significant WHOIS details extracted for {domain}")

    except whois.parser.PywhoisError as e:
        print_error(f"WHOIS lookup failed for {domain}: {e}. This might mean the domain is invalid or no WHOIS server responded.")
        logging.error(f"WHOIS lookup error for {domain}: {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred during WHOIS lookup for {domain}: {e}")
        logging.error(f"Unexpected error in WHOIS for {domain}: {e}")

def get_dns_records(domain):
    print_section_header("DNS Records")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    dns_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CNAME'] # Expanded types
    for rtype in dns_types:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                print_info(rtype, rdata.to_text())
        except dns.resolver.NoAnswer:
            print_info(rtype, "No records found.")
        except dns.resolver.NXDOMAIN:
            print_error(f"DNS lookup failed for {domain}: Non-existent Domain (NXDOMAIN).")
            logging.error(f"DNS NXDOMAIN for {domain}")
            return # If domain doesn't exist, no need to check other record types
        except dns.resolver.Timeout:
            print_error(f"DNS lookup for {rtype} timed out for {domain}.")
            logging.warning(f"DNS lookup timeout for {rtype} on {domain}")
        except dns.resolver.LifetimeTimeout: # Specific timeout for the resolver
            print_error(f"DNS resolver lifetime timed out for {rtype} on {domain}.")
            logging.warning(f"DNS resolver lifetime timeout for {rtype} on {domain}")
        except Exception as e:
            print_error(f"An error occurred during {rtype} DNS lookup for {domain}: {e}")
            logging.error(f"Unexpected error in DNS {rtype} lookup for {domain}: {e}")

def get_http_headers(url, retries=3, delay=5):
    print_section_header("HTTP Headers")
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=10, allow_redirects=True) # Increased timeout, follow redirects
            print_info("Final URL", r.url)
            print_info("Status Code", r.status_code)
            
            print(colored("\n--- General Headers ---", 'yellow'))
            for k, v in r.headers.items():
                print_info(k, v)

            print(colored("\n--- Security Headers ---", 'yellow'))
            security_headers = {
                'Content-Security-Policy': 'Not set (Missing)',
                'X-Frame-Options': 'Not set (Missing)',
                'Strict-Transport-Security': 'Not set (Missing)',
                'X-Content-Type-Options': 'Not set (Missing)',
                'Referrer-Policy': 'Not set (Missing)',
                'Permissions-Policy': 'Not set (Missing)',
                'Expect-CT': 'Not set (Missing)',
                'Feature-Policy': 'Not set (Missing)' # Older, but good to check
            }
            
            for h, default_msg in security_headers.items():
                if h in r.headers:
                    print_info(f"FOUND {h}", r.headers[h])
                else:
                    print_info(f"MISSING {h}", default_msg)
            
            # Additional checks
            if 'Server' in r.headers:
                print_info("Server Banner", r.headers['Server'])
            if 'X-Powered-By' in r.headers:
                print_info("X-Powered-By", r.headers['X-Powered-By'])
            
            return # Success, exit loop
        except requests.exceptions.Timeout:
            print_error(f"Attempt {attempt + 1}/{retries}: HTTP header fetch timed out for {url}.")
            logging.warning(f"HTTP header fetch timeout for {url}")
            if attempt < retries - 1:
                time.sleep(delay)
        except requests.exceptions.ConnectionError as e:
            print_error(f"Attempt {attempt + 1}/{retries}: Connection error for {url}: {e}.")
            logging.warning(f"HTTP connection error for {url}: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
        except requests.exceptions.RequestException as e:
            print_error(f"Attempt {attempt + 1}/{retries}: An HTTP request error occurred for {url}: {e}")
            logging.error(f"HTTP request error for {url}: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
        except Exception as e:
            print_error(f"An unexpected error occurred during HTTP header fetch for {url}: {e}")
            logging.error(f"Unexpected error in HTTP header fetch for {url}: {e}")
            return # Non-retryable error after initial attempts if unexpected

def port_scan(domain, ports, num_threads=20):
    print_section_header("Basic Port Scan")
    try:
        ip = socket.gethostbyname(domain)
        print_info("Resolved IP", ip)

        def scan_single_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) # More granular timeout control
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        print_success(f"Port {port} OPEN ({service})")
                    except OSError:
                        print_success(f"Port {port} OPEN (Unknown Service)")
                # else: print_info(f"Port {port} CLOSED") # Optional: too verbose
            except socket.timeout:
                pass # Port likely filtered or closed, no need to print error for timeout
            except socket.error as e:
                logging.debug(f"Socket error for port {port}: {e}") # Log detailed socket errors for debugging
            except Exception as e:
                logging.error(f"Unexpected error scanning port {port}: {e}")
            finally:
                sock.close()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(scan_single_port, ports)

    except socket.gaierror:
        print_error(f"Could not resolve hostname: {domain}. Skipping port scan.")
        logging.error(f"Could not resolve hostname {domain} for port scan.")
    except Exception as e:
        print_error(f"Port scan failed unexpectedly for {domain}: {e}")
        logging.error(f"Unexpected error in port scan for {domain}: {e}")

def find_directories(url, wordlist_paths, num_threads=50):
    print_section_header("Directory Discovery")
    if not url.endswith('/'):
        url += '/'

    all_paths = []
    for wl_path in wordlist_paths:
        if not os.path.exists(wl_path):
            print_error(f"Wordlist not found: {wl_path}. Skipping.")
            logging.warning(f"Wordlist not found: {wl_path}")
            continue
        try:
            with open(wl_path, 'r') as f:
                all_paths.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except Exception as e:
            print_error(f"Error reading wordlist {wl_path}: {e}")
            logging.error(f"Error reading wordlist {wl_path}: {e}")
            continue
    
    if not all_paths:
        print_error("No valid wordlists loaded for directory discovery. Skipping.")
        return

    print_info("Total paths to check", len(all_paths))

    def check_path(path):
        full_url = url + path
        try:
            # Use HEAD requests first to be less intrusive, fallback to GET if HEAD isn't supported/informative
            res = requests.head(full_url, timeout=5, allow_redirects=True)
            status_code = res.status_code
            if status_code in [200, 301, 302, 307, 308, 401, 403, 405]: # Added 405 Method Not Allowed
                # If HEAD is 405, try GET to confirm
                if status_code == 405:
                    res = requests.get(full_url, timeout=5, allow_redirects=True)
                    status_code = res.status_code

                if status_code == 200:
                    print_success(f"Found: {full_url} (200 OK)")
                elif status_code in [301, 302, 307, 308]:
                    location = res.headers.get('Location', 'N/A')
                    print_info(f"Redirect: {full_url}", f"{status_code} -> {location}")
                elif status_code == 403:
                    print_info(f"Forbidden: {full_url}", f"({status_code})")
                elif status_code == 401:
                    print_info(f"Unauthorized: {full_url}", f"({status_code})")
                elif status_code == 404: # Explicitly checking 404 to avoid excessive output, only print if we want to debug false positives
                    pass
                else:
                    print_info(f"Found (Other): {full_url}", f"({status_code})")

        except requests.exceptions.Timeout:
            logging.debug(f"Timeout checking {full_url}")
        except requests.exceptions.ConnectionError:
            logging.debug(f"Connection error checking {full_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error checking {full_url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in directory discovery for {full_url}: {e}")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        list(executor.map(check_path, all_paths)) # Use list() to ensure all futures complete

# === Report Generation ===
def generate_report(outdir, target_url, domain):
    print_section_header("Generating Summary Report")
    report_file = os.path.join(outdir, "summary_report.md")
    try:
        with open(report_file, "w") as f:
            f.write(f"# Reconnaissance Report for {target_url}\n\n")
            f.write(f"**Domain:** {domain}\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Output Directory:** `{outdir}/`\n\n")

            f.write("## Overview\n\n")

            # Summarize subdomains
            subdomain_file = f"{outdir}/subdomains.txt"
            if os.path.exists(subdomain_file) and os.path.getsize(subdomain_file) > 0:
                sub_count = sum(1 for line in open(subdomain_file))
                f.write(f"- Found **{sub_count}** unique subdomains.\n")
            else:
                f.write("- No subdomains identified by external tools.\n")

            # Summarize live hosts
            live_file = f"{outdir}/live.txt"
            if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
                live_count = sum(1 for line in open(live_file))
                f.write(f"- Identified **{live_count}** live hosts.\n")
            else:
                f.write("- No live hosts identified from subdomains (or subdomains not found).\n")

            f.write("\n## Key Findings\n\n")

            # Summarize Nuclei findings
            nuclei_file = f"{outdir}/nuclei.txt"
            if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
                f.write("### Nuclei Vulnerability Scan Summary\n")
                with open(nuclei_file, "r") as nf:
                    nuclei_findings = [line.strip() for line in nf if line.strip()]
                    if nuclei_findings:
                        # Basic parsing to categorize by severity or type
                        severity_counts = {}
                        for finding in nuclei_findings:
                            if '[' in finding and ']' in finding:
                                try:
                                    severity_tag = finding.split('[')[1].split(']')[0]
                                    severity_counts[severity_tag] = severity_counts.get(severity_tag, 0) + 1
                                except IndexError:
                                    pass # Malformed line
                        
                        if severity_counts:
                            for severity, count in sorted(severity_counts.items()):
                                f.write(f"- {severity}: {count} findings\n")
                            f.write("\n_See `nuclei.txt` for full details._\n\n")
                        else:
                            f.write("- Nuclei found issues, but no clear severity tags extracted. See `nuclei.txt` for details.\n\n")
                    else:
                        f.write("- Nuclei scan completed, but no findings reported.\n\n")
            else:
                f.write("- Nuclei scan results not available (tool might not have run or file empty).\n\n")

            # Summarize Nikto findings (basic)
            nikto_files = [f for f in os.listdir(outdir) if f.startswith('nikto_') and f.endswith('.txt')]
            if nikto_files:
                f.write("### Nikto Web Server Scan Summary\n")
                total_nikto_findings = 0
                for nk_file in nikto_files:
                    path = os.path.join(outdir, nk_file)
                    try:
                        with open(path, 'r') as nf:
                            findings = [line for line in nf if 'Nikto' not in line and '+' in line]
                            total_nikto_findings += len(findings)
                            if findings:
                                f.write(f"- Findings for `{nk_file.replace('nikto_', '').replace('.txt', '')}`: {len(findings)} items\n")
                    except Exception as e:
                        logging.error(f"Error reading Nikto file {path}: {e}")
                if total_nikto_findings > 0:
                    f.write(f"\n_Total Nikto findings across scanned hosts: {total_nikto_findings}. See `nikto_*.txt` files for full details._\n\n")
                else:
                    f.write("- Nikto scans completed, no specific findings reported.\n\n")
            else:
                f.write("- Nikto scan results not available.\n\n")

            # Summarize Interesting Wayback URLs
            wayback_file = f"{outdir}/interesting.txt"
            if os.path.exists(wayback_file) and os.path.getsize(wayback_file) > 0:
                f.write("### Interesting Wayback URLs\n")
                with open(wayback_file, "r") as wf:
                    interesting_urls = [line.strip() for line in wf if line.strip()]
                    if interesting_urls:
                        f.write(f"- Found **{len(interesting_urls)}** potentially interesting URLs (PHP, ASP, JS, TXT, BAK, etc.):\n")
                        for i, url in enumerate(interesting_urls[:10]): # List top 10
                            f.write(f"  - {url}\n")
                        if len(interesting_urls) > 10:
                            f.write(f"  ... and {len(interesting_urls) - 10} more. See `wayback.txt` and `interesting.txt` for full list.\n\n")
                    else:
                        f.write("- No interesting URLs found via Wayback Machine.\n\n")
            else:
                f.write("- Wayback URL results not available.\n\n")

            f.write("## Detailed Output Files\n\n")
            f.write("All detailed outputs are saved in the main output directory:\n")
            for root, dirs, files in os.walk(outdir):
                for file in sorted(files):
                    if file.endswith(('.txt', '.html')):
                        f.write(f"- `{file}`\n")
                break # Only list top level files for brevity

        print_success(f"Summary report generated successfully: {report_file}")
        logging.info(f"Summary report generated at {report_file}")
    except Exception as e:
        print_error(f"Failed to generate summary report: {e}")
        logging.error(f"Error generating summary report: {e}")


# === Main Entry Point ===

def main():
    try: # This try-except block wraps the entire main function's execution
        print_banner()

        parser = argparse.ArgumentParser(description="Advanced Bug Bounty Reconnaissance Script")
        parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., https://example.com)")
        parser.add_argument("-o", "--output", help="Output directory name (default: recon_<domain>_<timestamp>)")
        parser.add_argument("--no-active", action="store_true", help="Skip active reconnaissance (port scan, directory bruteforce, external active tools like Nmap, FFUF, Nikto, Nuclei)")
        parser.add_argument("--config", help="Path to a JSON configuration file for custom settings")
        parser.add_argument("--skip-tool-check", action="store_true", help="Skip checking if external tools are installed")
        # THIS IS THE LINE THAT WAS ADDED/MODIFIED:
        parser.add_argument("--xss-script", help="Path to a secondary XSS scanning script to run after recon completes (e.g., ./xss_scanner_script.py)")
        
        args = parser.parse_args()

        target_url = args.target.strip()
        
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            print_error("URL must include http:// or https://")
            sys.exit(1)

        try:
            domain = target_url.split('//')[1].split('/')[0]
        except IndexError:
            print_error("Invalid target URL format. Please provide a full URL like https://example.com")
            sys.exit(1)

        DATE = datetime.now().strftime("%Y-%m-%d_%H-%M")
        OUTDIR = args.output if args.output else f"recon_{domain}_{DATE}"
        
        # Create output directory and configure file logging
        try:
            os.makedirs(OUTDIR, exist_ok=True)
            file_handler = logging.FileHandler(f"{OUTDIR}/recon.log")
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logging.getLogger().addHandler(file_handler)
            print_success(f"Output will be saved in: {OUTDIR}/ and logs in {OUTDIR}/recon.log")
            logging.info(f"Starting reconnaissance for {target_url}. Output directory: {OUTDIR}")
        except Exception as e:
            print_error(f"Failed to create output directory {OUTDIR}: {e}")
            sys.exit(1)

        # --- Load Configuration ---
        config = {
            'ports': [21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443],
            'directory_wordlists': ['/usr/share/wordlists/dirb/common.txt', 'wordlists/common.txt', 'wordlists/dirbuster/directory-list-2.3-small.txt'], # Fallback paths
            'active_threads': {
                'port_scan': 50,
                'directory_discovery': 100
            },
            'external_tools': ["subfinder", "httpx", "naabu", "nmap", "ffuf", "nikto", "nuclei", "waybackurls", "dig", "whois"]
        }

        if args.config:
            try:
                with open(args.config, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config) # Override defaults with user config
                print_success(f"Loaded custom configuration from {args.config}")
                logging.info(f"Loaded custom configuration from {args.config}")
            except FileNotFoundError:
                print_error(f"Configuration file not found: {args.config}. Using default settings.")
                logging.error(f"Config file not found: {args.config}")
            except json.JSONDecodeError:
                print_error(f"Error parsing configuration file: {args.config}. Ensure it's valid JSON. Using default settings.")
                logging.error(f"Error parsing config file: {args.config}")
            except Exception as e:
                print_error(f"An unexpected error occurred loading config {args.config}: {e}. Using default settings.")
                logging.error(f"Unexpected error loading config {args.config}: {e}")

        # --- Check External Tools ---
        if not args.skip_tool_check:
            print_section_header("Checking External Tools")
            missing_tools = []
            for tool in config['external_tools']:
                if not check_tool_installed(tool):
                    missing_tools.append(tool)
            
            if missing_tools:
                print_error(f"The following external tools are not found in your PATH: {', '.join(missing_tools)}.")
                print_error("Some reconnaissance steps will be skipped or may fail. Please install them or ensure they are in your PATH.")
                logging.warning(f"Missing external tools: {', '.join(missing_tools)}")
            else:
                print_success("All required external tools found in PATH.")

        print(colored(f"\n[*] Starting Reconnaissance on {target_url}", "magenta"))
        logging.info(f"Starting reconnaissance for {target_url}")

        # --- Passive Recon (Script) ---
        get_whois_info(domain)
        get_dns_records(domain)
        get_http_headers(target_url)

        # --- Active Recon (Script) ---
        if not args.no_active:
            port_scan(domain, config['ports'], num_threads=config['active_threads']['port_scan'])
            # Ensure directory_wordlists are handled correctly if user provides a single string
            dir_wordlists_to_use = config['directory_wordlists']
            if isinstance(dir_wordlists_to_use, str):
                dir_wordlists_to_use = [dir_wordlists_to_use] # Make it a list if it's a string
            find_directories(target_url, dir_wordlists_to_use, num_threads=config['active_threads']['directory_discovery'])
        else:
            print_info("Skipping Active Reconnaissance (scripted)", "As requested by --no-active flag.")

        # --- Passive Recon (External) ---
        print_section_header("External Passive Recon")
        
        if check_tool_installed("whois"):
            run_cmd(f"whois {domain}", f"{OUTDIR}/whois_external.txt")
        else:
            print_error("Skipping external whois command: tool not found.")

        if check_tool_installed("dig"):
            run_cmd(f"dig {domain} any", f"{OUTDIR}/dns_external.txt")
        else:
            print_error("Skipping external dig command: tool not found.")

        # Subdomain enumeration with multiple tools
        subdomain_tools_run = False
        if check_tool_installed("subfinder"):
            run_cmd(f"subfinder -d {domain} -o {OUTDIR}/subfinder.txt")
            subdomain_tools_run = True
        else:
            print_error("Skipping subfinder: tool not found.")

        if check_tool_installed("assetfinder"):
            run_cmd(f"assetfinder --subs-only {domain} >> {OUTDIR}/subfinder.txt")
            subdomain_tools_run = True
        else:
            print_error("Skipping assetfinder: tool not found.")
        
        if check_tool_installed("amass"):
            # Amass can be very slow, consider running in background or making optional
            run_cmd(f"amass enum -passive -d {domain} -o {OUTDIR}/amass.txt")
            if os.path.exists(f"{OUTDIR}/amass.txt"):
                run_cmd(f"cat {OUTDIR}/amass.txt >> {OUTDIR}/subfinder.txt")
            subdomain_tools_run = True
        else:
            print_error("Skipping amass: tool not found.")
        
        # Combine and unique subdomains if any tools ran
        if subdomain_tools_run and os.path.exists(f"{OUTDIR}/subfinder.txt"):
            run_cmd(f"sort -u {OUTDIR}/subfinder.txt > {OUTDIR}/subdomains.txt")
            # Clean up temporary subfinder.txt
            # os.remove(f"{OUTDIR}/subfinder.txt")
        elif not subdomain_tools_run:
            print_info("Subdomain enumeration tools", "No external subdomain tools ran due to missing executables.")
        else:
            print_info("Subdomain enumeration", "No subdomains found by external tools (subfinder.txt was empty or not created).")


        # Check if subdomains.txt is empty or missing, fallback logic
        subdomain_file = f"{OUTDIR}/subdomains.txt"
        urls_for_active_scan = [target_url] # Default to target_url

        if os.path.isfile(subdomain_file) and os.path.getsize(subdomain_file) > 0:
            if check_tool_installed("httpx"):
                print_info("Processing Live Hosts", "Using httpx on found subdomains.")
                run_cmd(f"httpx -silent -l {subdomain_file} -title -status-code -tech-detect -o {OUTDIR}/live.txt")
                live_file = f"{OUTDIR}/live.txt"
                if os.path.isfile(live_file) and os.path.getsize(live_file) > 0:
                    with open(live_file, 'r') as f:
                        # Take up to 10 live URLs for more focused active scans to avoid overwhelming
                        urls_for_active_scan = [line.strip().split(' ')[0] for line in f.readlines() if line.strip()][:10]
                    print_info("Selected live URLs for active scans", ", ".join(urls_for_active_scan))
                else:
                    print_error(f"live.txt was created but is empty. Falling back to target_url for FFUF, Nikto, Nuclei.")
                    logging.warning("live.txt empty, falling back to target_url for active scans.")
            else:
                print_error("Skipping httpx: tool not found. Falling back to target_url for active scans.")
                logging.warning("httpx not found, falling back to target_url for active scans.")
        else:
            print_error(f"No subdomains found in {subdomain_file}. Falling back to main target_url for active scans.")
            logging.warning("No subdomains found, falling back to target_url for active scans.")

        # --- Active Recon (External) ---
        if not args.no_active:
            print_section_header("External Active Recon")
            
            if os.path.isfile(subdomain_file) and os.path.getsize(subdomain_file) > 0 and check_tool_installed("naabu"):
                run_cmd(f"naabu -list {subdomain_file} -o {OUTDIR}/naabu_ports.txt")
            elif not check_tool_installed("naabu"):
                print_error("Skipping naabu: tool not found.")
            else:
                print_info("Naabu scan", "Skipped due to no subdomains found.")


            if os.path.isfile(f"{OUTDIR}/naabu_ports.txt") and os.path.getsize(f"{OUTDIR}/naabu_ports.txt") > 0 and check_tool_installed("nmap"):
                print_info("Nmap Scan", "Running Nmap on discovered Naabu ports (might take time).")
                # Nmap command should take IP:port format for -iL, naabu provides host:port.
                # A simple way for Nmap is to scan IPs and then specify common ports.
                # For specific open ports from Naabu, a more complex parse of naabu_ports.txt is needed.
                # For simplicity, we'll run nmap on the domain's IP with common ports or on live URLs.
                
                # Extract IPs from naabu_ports.txt if it contains only IPs or host:port
                nmap_targets = []
                try:
                    with open(f"{OUTDIR}/naabu_ports.txt", 'r') as f:
                        for line in f:
                            if ':' in line: # host:port
                                nmap_targets.append(line.strip().split(':')[0])
                            else: # just host/ip
                                nmap_targets.append(line.strip())
                    nmap_targets = list(set(nmap_targets)) # Unique IPs/hosts
                    if nmap_targets:
                        # Write to a temporary file for nmap -iL
                        with open(f"{OUTDIR}/nmap_targets.txt", "w") as f_nmap:
                            for target in nmap_targets:
                                f_nmap.write(f"{target}\n")
                        run_cmd(f"nmap -iL {OUTDIR}/nmap_targets.txt -sC -sV -oN {OUTDIR}/nmap.txt")
                    else:
                        print_info("Nmap Scan", "No valid targets found from naabu_ports.txt for Nmap.")
                except Exception as e:
                    print_error(f"Error preparing Nmap targets from naabu_ports.txt: {e}")
                    logging.error(f"Error preparing Nmap targets: {e}")
            elif not check_tool_installed("nmap"):
                print_error("Skipping nmap: tool not found.")
            else:
                print_info("Nmap Scan", "Skipped as no open ports found by Naabu.")

            # Directory fuzzing with FFUF
            if check_tool_installed("ffuf"):
                print_info("FFUF Directory Fuzzing", "Running FFUF on selected live URLs (or main target).")
                for base_url in urls_for_active_scan:
                    clean_name = base_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
                    out_html = f"{OUTDIR}/ffuf_{clean_name}.html"
                    # Use first available wordlist path
                    ffuf_wordlist = next((wl for wl in config['directory_wordlists'] if os.path.exists(wl)), None)
                    if ffuf_wordlist:
                        print_info("FFUF Wordlist", ffuf_wordlist)
                        run_cmd(f"ffuf -w {ffuf_wordlist} -u {base_url}/FUZZ -o {out_html} -of html -recursion -recursion-depth 2 -v -e .php,.html,.js,.json,.txt,.bak", out_html)
                    else:
                        print_error("No valid wordlist found for FFUF.")
            else:
                print_error("Skipping FFUF: tool not found.")

            # Vuln Scans (Nikto, Nuclei)
            for base_url in urls_for_active_scan:
                clean_name = base_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
                if check_tool_installed("nikto"):
                    run_cmd(f"nikto -h {base_url}", f"{OUTDIR}/nikto_{clean_name}.txt")
                else:
                    print_error(f"Skipping Nikto for {base_url}: tool not found.")
            
            if check_tool_installed("nuclei"):
                # Nuclei can take a list of targets from live.txt or a single target
                if os.path.isfile(f"{OUTDIR}/live.txt") and os.path.getsize(f"{OUTDIR}/live.txt") > 0:
                    print_info("Nuclei Scan", "Running Nuclei on live hosts (from live.txt).")
                    run_cmd(f"nuclei -l {OUTDIR}/live.txt -o {OUTDIR}/nuclei.txt -silent -severity critical,high,medium") # Filter by severity
                else:
                    print_info("Nuclei Scan", "Running Nuclei on main target URL.")
                    run_cmd(f"echo {target_url} | nuclei -o {OUTDIR}/nuclei.txt -silent -severity critical,high,medium")
            else:
                print_error("Skipping Nuclei: tool not found.")
        else:
            print_info("Skipping Active Reconnaissance (external tools)", "As requested by --no-active flag.")

        # Wayback URLs
        if check_tool_installed("waybackurls"):
            print_section_header("Wayback Machine & Interesting Files")
            run_cmd(f"waybackurls {domain} > {OUTDIR}/wayback.txt")
            if os.path.exists(f"{OUTDIR}/wayback.txt"):
                run_cmd(f"grep -Ei '\\.php|\\.asp|\\.aspx|\\.jsp|\\.json|\\.txt|\\.xml|\\.log|\\.bak|\\.old|\\.zip|\\.rar|\\.7z|\\.sql|\\.git|\\.env|\\.conf|\\.yml|\\.yaml' {OUTDIR}/wayback.txt > {OUTDIR}/interesting.txt")
            else:
                print_error("wayback.txt not found, skipping interesting file extraction.")
        else:
            print_error("Skipping waybackurls: tool not found.")

        # --- Generate Final Report ---
        generate_report(OUTDIR, target_url, domain)

        print_success(f"\nReconnaissance Complete! All outputs and logs saved in: {OUTDIR}/")
        logging.info(f"Reconnaissance completed for {target_url}. Output directory: {OUTDIR}")

        # --- Call Secondary Script (e.g., XSS Scanner) ---
        if args.xss_script:
            xss_script_path = args.xss_script
            if os.path.exists(xss_script_path):
                print_section_header("Running Secondary XSS Scan Script")
                # Pass the output directory and target URL to the XSS script
                # The XSS script should be designed to accept these arguments
                xss_command = [sys.executable, xss_script_path, "--output-dir", OUTDIR, "--target-url", target_url]
                print_info("Executing XSS script", " ".join(xss_command))
                try:
                    # Use subprocess.run to execute the XSS script and wait for its completion
                    # capture_output=False so the XSS script's output goes directly to console
                    subprocess.run(xss_command, check=True, capture_output=False)
                    print_success("Secondary XSS scan script completed successfully.")
                except subprocess.CalledProcessError as e:
                    print_error(f"Secondary XSS scan script failed with exit code {e.returncode}.")
                    logging.error(f"XSS script failed: {e}")
                except FileNotFoundError:
                    print_error(f"Python interpreter not found to run {xss_script_path}.")
                    logging.error(f"Python interpreter not found for XSS script.")
                except Exception as e:
                    print_error(f"An unexpected error occurred while running XSS script: {e}")
                    logging.error(f"Unexpected error running XSS script: {e}")
            else:
                print_error(f"Secondary XSS script not found at: {xss_script_path}. Skipping XSS scan.")
                logging.error(f"XSS script not found: {xss_script_path}")
        else:
            print_info("Secondary XSS script", "No XSS script path provided (--xss-script not used). Skipping.")


    except KeyboardInterrupt:
        print_error("Scan interrupted by user (Ctrl+C). Exiting gracefully.")
        logging.warning("Scan interrupted by user.")
    except Exception as e:
        print_error(f"An unexpected critical error occurred: {e}")
        logging.critical(f"Critical error in main execution: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
