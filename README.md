# VirusTotal Directory Scanner (`vt-dir-scanner`)

> **Automated, rate-limit friendly Python CLI tool for recursive directory scanning and deep threat intelligence telemetry extraction via VirusTotal v3 API.**

---

## 📌 Overview

**vt-dir-scanner** is a lightweight Python utility designed to scan local directories using VirusTotal's official v3 API (`vt-py`). 

Instead of uploading physical files to the cloud—which consumes bandwidth, violates privacy, and quickly hits API limits—the scanner computes SHA-256 hashes locally in a memory-efficient stream. It queries VirusTotal solely for existing threat intelligence telemetry, sandbox behavior records, YARA rules, and multi-engine AV detection stats.

---

## ✨ Key Features

* 🔒 **Zero-Upload & Privacy-First:** Files are hashed locally in 4 KB chunks. No file content ever leaves your machine.
* ⚡ **Memory Efficient:** Processes large binaries and multi-gigabyte ISO files without RAM spikes.
* ⏱️ **Rate-Limit Safe:** Built-in delay mechanism (15 seconds between queries) prevents free API accounts from exceeding the 4 requests/minute (500/day) threshold.
* 🛡️ **Deep Threat Intelligence Telemetry:**
  * **General Metadata:** File type (Magic/MIME), exact size, community reputation score, tags, known file names.
  * **History Tracking:** First/last submission timestamps, last full scan date, total submission count.
  * **Pivoting & Hashes:** SHA-256, MD5, Imphash (PE Import Table hash), ssdeep (fuzzy hashing), vhash.
  * **Digital Signatures:** Certificate issuer, product verification, and spoofing checks.
  * **YARA Rules & Behavioral Analysis:** Crowdsourced YARA rule hits and sandbox execution verdicts (e.g., Cuckoo, Yomi).
  * **AV Engine Details:** Itemized detection lists showing specific security vendors and identified malware families.

---

## 🛠️ Prerequisites

* **Python 3.8+**
* A free or premium **VirusTotal API Key** ([Get one here](https://www.virustotal.com/gui/my-apikey))

---

## 📥 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/vt-dir-scanner.git
   cd vt-dir-scanner
   ```

2. **(Optional) Create a virtual environment:**
   * **Windows:**
     ```cmd
     python -m venv .venv
     .venv\Scripts\activate
     ```
   * **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   > ⚠️ **CRITICAL:** Make sure to install `vt-py`, **NOT** `vt`. Installing `vt` will cause an `AttributeError`.

   ```bash
   pip install vt-py
   ```

---

## ⚙️ Configuration

Open `virustotal.py` in your code editor and update the following variables at the top of the file:

```python
# Configuration
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY_HERE'
FOLDER_PATH = r'C:\Path\To\Target\Folder'  # Path to the directory you want to scan
SLEEP_TIME = 15  # Keep at 15 for free API accounts (4 req/min limit)
```

---

## 🚀 How to Run

Execute the script from your terminal:

```bash
python virustotal.py
```

---

## 📊 Sample Terminal Output

```text
================================================================================
🚀 ANALYSIS STARTED: C:\Users\Kamil\Desktop\PublicClient\Updater.exe
================================================================================

[1] 📋 BASIC METADATA
    - Main VT Name  : Updater.exe
    - File Type     : Win32 EXE (PE32+ executable (GUI) x86-64, for MS Windows)
    - File Size     : 12472.78 KB
    - Community     : Reputation 0 pts
    - VT Tags       : overlay, 64bits, peexe
    - Other Names   : Updater.exe, Updater (1).exe

[2] 📅 FILE HISTORY
    - First Submitted to VT : 2026-10-26 20:22:38
    - Last Submitted to VT  : 2026-10-27 17:24:24
    - Last Full AV Scan     : 2026-10-27 17:24:32
    - Submission Count      : 2

[3] 🔍 IDENTIFIERS & CODE SIMILARITY
    - SHA-256: e9dab305f1a37c1d11bf85ee8959a647c997dad33ade98d8c7b22b8a235804ab
    - MD5    : c2fee4a7dc1f4ce44b1e50b6e605b63a
    - vhash  : 017076655d155d0575504013z3006dmz2gz
    - ssdeep : 393216:DpGQW8+1AnGCnGjxMwBWTLwqkSNE28aXB...
    - Imphash: 1dcd477cce07724ec6b817b3be71540e (Import Table Hash)

[5] ☢️  YARA RULE MATCHES (Crowdsourced)
    - Match: PyInstaller (Author: @bartblaze)

[6] 🪲  MALICIOUS BEHAVIOR (SANDBOXES)
    - [THREAT] Sandbox 'Yomi Hunter' flagged the file as malicious

[7] 🛡️  ANTIVIRUS ENGINE VERDICTS
    [!] WARNING: 3 engines detected threats, 0 marked suspicious (out of 75)
    --- Detection Details ---
        * Bkav: W32.Malware.97AD11D (MALICIOUS)
        * CrowdStrike: win/malicious_confidence_60% (D) (MALICIOUS)
        * APEX: Malicious (MALICIOUS)

--- Waiting 15 seconds (API Limit) ---
```

---

## ❓ Troubleshooting

### `AttributeError: module 'vt' has no attribute 'Client'`
This happens if you installed the wrong package (`vt` instead of `vt-py`).
**Fix:**
```bash
pip uninstall vt
pip install vt-py
```

### `vt.error.APIError: QuotaExceededError`
You have hit your VirusTotal API limit. Ensure `SLEEP_TIME = 15` is set if using a free public API key (4 requests/minute, 500 requests/day).

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
