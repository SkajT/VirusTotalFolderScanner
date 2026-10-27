import os
import hashlib
import time
import datetime
import vt

# Configuration
API_KEY = 'Your API KEY'
FOLDER_PATH = r'C:\Path\To\Folder'
SLEEP_TIME = 15  # 15-second delay = max 4 requests per minute for free API tier


def get_file_hash(file_path):
    """Calculates SHA-256 hash for a file in 4 KB chunks."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f" [!] File read error {file_path}: {e}")
        return None


def ts_to_date(date_obj):
    """Converts VirusTotal date object to a human-readable format.
    Supports both raw Unix timestamps (int/float) and datetime objects.
    """
    if not date_obj:
        return "No data"

    # If vt-py returned a datetime object directly
    if isinstance(date_obj, datetime.datetime):
        return date_obj.strftime('%Y-%m-%d %H:%M:%S')

    # If vt-py returned a Unix timestamp (int or float)
    if isinstance(date_obj, (int, float)):
        return datetime.datetime.fromtimestamp(date_obj).strftime('%Y-%m-%d %H:%M:%S')

    return "Unknown date format"


def scan_directory(folder_path):
    with vt.Client(API_KEY) as client:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)

                print(f"\n{'=' * 80}")
                print(f"🚀 ANALYSIS STARTED: {file_path}")
                print(f"{'=' * 80}")

                file_hash = get_file_hash(file_path)
                if not file_hash:
                    continue

                try:
                    # Fetch FULL object from VirusTotal
                    file_obj = client.get_object(f"/files/{file_hash}")

                    # --- [1] GENERAL METADATA ---
                    file_type = getattr(file_obj, 'type_description', 'Unknown')
                    magic = getattr(file_obj, 'magic', 'N/A')
                    size_kb = getattr(file_obj, 'size', 0) / 1024
                    meaningful_name = getattr(file_obj, 'meaningful_name', 'N/A')
                    names = getattr(file_obj, 'names', [])
                    tags = getattr(file_obj, 'tags', [])
                    reputation = getattr(file_obj, 'reputation', 0)
                    times_submitted = getattr(file_obj, 'times_submitted', 0)

                    print(f"\n[1] 📋 BASIC METADATA")
                    print(f"    - Main VT Name  : {meaningful_name}")
                    print(f"    - File Type     : {file_type} ({magic})")
                    print(f"    - File Size     : {size_kb:.2f} KB")
                    print(f"    - Community     : Reputation {reputation} pts")
                    print(f"    - VT Tags       : {', '.join(tags) if tags else 'None'}")
                    print(f"    - Other Names   : {', '.join(names[:5])}{' ...' if len(names) > 5 else ''}")

                    # --- [2] FILE HISTORY ---
                    first_seen = ts_to_date(getattr(file_obj, 'first_submission_date', 0))
                    last_seen = ts_to_date(getattr(file_obj, 'last_submission_date', 0))
                    last_scan = ts_to_date(getattr(file_obj, 'last_analysis_date', 0))

                    print(f"\n[2] 📅 FILE HISTORY")
                    print(f"    - First Submitted to VT : {first_seen}")
                    print(f"    - Last Submitted to VT  : {last_seen}")
                    print(f"    - Last Full AV Scan     : {last_scan}")
                    print(f"    - Submission Count      : {times_submitted}")

                    # --- [3] ADVANCED HASHES (Pivoting) ---
                    print(f"\n[3] 🔍 IDENTIFIERS & CODE SIMILARITY")
                    print(f"    - SHA-256: {file_hash}")
                    print(f"    - MD5    : {getattr(file_obj, 'md5', 'N/A')}")
                    print(f"    - vhash  : {getattr(file_obj, 'vhash', 'N/A')}")
                    print(f"    - ssdeep : {getattr(file_obj, 'ssdeep', 'N/A')}")

                    pe_info = getattr(file_obj, 'pe_info', {})
                    if pe_info and 'imphash' in pe_info:
                        print(f"    - Imphash: {pe_info.get('imphash')} (Import Table Hash)")

                    # --- [4] DIGITAL SIGNATURE ---
                    sig_info = getattr(file_obj, 'signature_info', {})
                    if sig_info:
                        print(f"\n[4] 🔐 DIGITAL SIGNATURE")
                        print(f"    - Certificate Issuer : {sig_info.get('issuers', 'N/A')}")
                        print(f"    - Product / Owner    : {sig_info.get('product', 'N/A')}")
                        print(
                            f"    - Certificate Valid? : {'YES' if sig_info.get('verified') else 'NO (Possible spoofing!)'}")

                    # --- [5] YARA RULES & BEHAVIORAL ANALYSIS (SANDBOXES) ---
                    yara_results = getattr(file_obj, 'crowdsourced_yara_results', [])
                    if yara_results:
                        print(f"\n[5] ☢️  YARA RULE MATCHES (Crowdsourced)")
                        for yara in yara_results:
                            print(
                                f"    - Match: {yara.get('rule_name')} (Author: {yara.get('author', 'Unknown')})")

                    sandbox_verdicts = getattr(file_obj, 'sandbox_verdicts', {})
                    if sandbox_verdicts:
                        malicious_sandboxes = [sb for sb, data in sandbox_verdicts.items() if
                                               data.get('category') == 'malicious']
                        if malicious_sandboxes:
                            print(f"\n[6] 🪲  MALICIOUS BEHAVIOR (SANDBOXES)")
                            for sb in malicious_sandboxes:
                                print(f"    - [THREAT] Sandbox '{sb}' flagged the file as malicious")

                    # --- [7] ANTIVIRUS ENGINE VERDICTS ---
                    stats = file_obj.last_analysis_stats
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())

                    print(f"\n[7] 🛡️  ANTIVIRUS ENGINE VERDICTS")
                    if malicious > 0 or suspicious > 0:
                        print(
                            f"    [!] WARNING: {malicious} engines detected threats, {suspicious} marked suspicious (out of {total})")
                        print(f"    --- Detection Details ---")
                        results = file_obj.last_analysis_results
                        for engine, data in results.items():
                            cat = data.get('category')
                            if cat in ['malicious', 'suspicious']:
                                res = data.get('result', 'No name')
                                print(f"        * {engine}: {res} ({cat.upper()})")
                    else:
                        print(f"    [+] CLEAN FILE. None of the {total} engines detected threats.")

                except vt.APIError as e:
                    if e.code == 'NotFoundError':
                        print("\n [?] UNKNOWN FILE: SHA-256 hash not found in VirusTotal database.")
                    else:
                        print(f"\n [!] VT API Error: {e}")

                print(f"\n--- Waiting {SLEEP_TIME} seconds (API Limit) ---")
                time.sleep(SLEEP_TIME)


if __name__ == '__main__':
    scan_directory(FOLDER_PATH)
