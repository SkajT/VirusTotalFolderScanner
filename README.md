# VirusTotal Directory Scanner (`vt-dir-scanner`)

A CLI tool written in Python for recursively scanning local directories and extracting deep Threat Intelligence telemetry from VirusTotal (v3 API) using the official `vt-py` library.

The scanner relies on local SHA-256 hash calculation, eliminating the need to upload files, saving bandwidth, and preserving privacy.

## 🚀 Features

* **Zero-Upload Scanning (SHA-256):** Files are read via 4 KB streams—no RAM spikes even when processing multi-gigabyte binaries.
* **Rate-Limit Friendly:** Built-in delays safeguard free API accounts against exceeding the 4 requests/minute (500/day) threshold.
* **Deep Threat Intelligence Telemetry:**
  * **Metadata:** File type (MIME/Magic), file size, community reputation score, VT tags, known filenames across samples.
  * **History:** First/last submission dates, last analysis date, submission count.
  * **Pivoting & Hashes:** SHA-256, MD5, Imphash (PE import table hash), ssdeep (fuzzy hashing), vhash.
  * **Digital Signatures:** Certificate issuer verification and chain validation (detecting signature spoofing).
  * **YARA Rules:** Crowdsourced YARA rule hits from threat researchers.
  * **Behavioral Analysis (Sandboxes):** Execution verdicts from automated sandbox environments.
  * **AV Detection Engine:** Itemized list of specific security vendors and their detection signatures.

## 🛠️ Requirements & Installation

* Python 3.8+
* Official `vt-py` library

```bash
# IMPORTANT: Install 'vt-py', NOT 'vt'
pip install vt-py
