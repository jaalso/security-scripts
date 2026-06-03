# security-scripts

# 🐍 Python Security Scripts
> Security-focused Python scripts for offensive and defensive operations ·  

---

## 📁 Tools

| # | Tool | Description | Status |
|---|---|---|---|
| 01 | [log-enricher](#01--log-enricher) | Enrich CSV auth logs with IP geolocation · flag non-Swiss access | ✅ Complete |
| 02 | hashfile.py | SHA-256 · SHA-1 · MD5 hash computation for file triage | 🔜 Planned |
| 03 | dnslookup.py | Bulk DNS A-record resolution with suspicious TLD detection | 🔜 Planned |
| 04 | certinfo.py | TLS certificate subject · issuer · expiry extraction | 🔜 Planned |
| 05 | urlrep.py | URL reputation via URLscan.io + VirusTotal API | 🔜 Planned |

---

### 01 · log-enricher

**Tech stack:** Python 3.13 · requests · ip-api.com REST API · csv · sys · time  
**Context:** SCI - Module 7 Scripting & Automation (Class 2511)  

A Python tool that enriches CSV log files with IP geolocation data, flagging non-Swiss access for security review.

**The Problem:**  
Raw security logs contain IP addresses, but an analyst can't tell from `185.137.62.10` alone
whether that's normal business traffic or suspicious access from a high-risk jurisdiction.
Manually looking up each IP via WHOIS or a web service is slow and unscalable.
For a pharmaceutical company with thousands of daily authentication events, this is unworkable.

**The Solution:**  
Read a CSV of authentication events → call ip-api.com for each unique IP → cache results →
respect rate limits → print timestamped alerts for any non-Swiss IP.
Output is designed to be piped directly into SIEM ingestion or an analyst's triage queue.

**Example Output:**

```bash
python log_enricher.py logfile.csv
```

```
[2025-09-29T08:00:12] - IP: 185.6.233.4 (Luxembourg, Luxembourg) - User: alice - Event: login_success
[2025-09-29T08:01:05] - IP: 188.64.128.68 (Russia, Novgorod Oblast) - User: bob - Event: login_failure
[2025-09-29T08:05:37] - IP: 185.46.212.34 (Netherlands, North Holland) - User: henry - Event: download
[2025-09-29T08:09:27] - IP: 185.137.62.10 (Iran, Kermanshah Province) - User: maria - Event: download
[2025-09-29T08:11:45] - IP: 185.220.101.6 (Germany, Brandenburg) - User: paul - Event: download
... (14 alerts total · 15 Swiss IPs filtered silently)
```

> The Iran-Kermanshah download alert is the kind of signal that triggers immediate investigation in a real engagement.

**Features:**

| Feature | Implementation |
|---|---|
| File error handling | Three distinct exception types — `FileNotFoundError` · `PermissionError` · `OSError` |
| API error handling | Catches `requests.exceptions.RequestException` — timeouts · DNS failures · connection errors |
| Request timeout | 5-second per-request timeout — prevents indefinite hangs |
| Result caching | In-memory dict keyed by IP — repeated IPs looked up only once |
| Rate limiting | 1.35-second sleep between API calls (60sec / 45req) — stays within ip-api.com free tier |
| CLI usability | Validates argument count · prints usage on missing input · `sys.exit(1)` for proper error codes |

**Installation:**

```bash
git clone https://github.com/jaalso/security-scripts
cd security-scripts/log-enricher
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install requests
python log_enricher.py logfile.csv
```

**Source:**

```python
import sys
import csv
import time
import requests

# Check if a filepath argument was provided
if len(sys.argv) < 2:
    print("Usage: python log_enricher.py <csv_file>")
    sys.exit(1)

filepath = sys.argv[1]

# Open and parse the CSV file
try:
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
except FileNotFoundError:
    print(f"Error: file '{filepath}' not found.")
    sys.exit(1)
except PermissionError:
    print(f"Error: permission denied reading '{filepath}'")
    sys.exit(1)
except OSError as e:
    print(f"Error reading '{filepath}': {e}")
    sys.exit(1)

# Cache for IP lookups - avoid duplicate API calls
ip_cache = {}

# Loop through each row in the CSV
for row in rows:
    ip = row["src_ip"]

    # Check if we've already looked up this IP
    if ip in ip_cache:
        data = ip_cache[ip]
    else:
        # Cache miss - call ip-api.com for this IP
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = requests.get(url, timeout=5)
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"API error for {ip}: {e}")
            continue
        ip_cache[ip] = data
        time.sleep(1.35)

    # Extract country and region from the lookup result
    country = data.get("country", "Unknown")
    region = data.get("regionName", "Unknown")

    # Flag non-Swiss IPs
    if country != "Switzerland":
        print(
            f"[{row['timestamp']}] - IP: {ip} "
            f"({country}, {region}) - "
            f"User: {row['username']} - "
            f"Event: {row['event']}"
        )
```

**Design Decisions:**

**`csv.DictReader` over `csv.reader`**  
Returns each row as a dictionary keyed by column name — `row["src_ip"]` instead of `row[1]`.
Survives column reordering in source data and self-documents what the code is doing.

**In-memory dict cache**  
Sufficient for log files up to millions of rows. For larger workloads, cache would migrate to Redis or SQLite.
Cache key is the IP string; value is the full parsed JSON — enabling future filters by ISP or ASN without re-calling the API.

**`.get()` over bracket access for API response fields**  
`data.get("country", "Unknown")` handles ip-api failure responses gracefully.
Bracket access would raise `KeyError` and crash mid-batch.

**Hardcoded filter (Switzerland) over config file**  
The brief specified a fixed Swiss baseline. A production version would accept a config file with an allowlist
of approved countries, ASN allowlist for cloud providers, and deny list for high-risk jurisdictions.

**Limitations & Future Work:**

- **HTTP-only API** — ip-api.com free tier limitation. HTTPS requires paid tier for production use
- **No retry logic** — failed lookups logged but not retried. Production would use exponential backoff with jitter
- **In-memory cache only** — lost on script restart. SQLite or Redis for persistent batch jobs
- **Single-threaded** — `aiohttp` async approach would reduce wall-clock runtime for very large files
- **Hardcoded filter** — production version would accept allowlists, deny lists, and impossible-travel detection

**What This Demonstrates:**

The read → enrich → filter → alert pattern is the foundation of nearly every detection-engineering
pipeline in production — from Wazuh rule enrichment to bespoke SOAR playbooks.

This script was written without IDE autocomplete on the logic, without copy-pasting from online sources,
and without AI-generated structural decisions. Every line was typed deliberately, with a pseudocode plan
first and a function-by-function build afterwards.

---

## 🧰 Tools Used

| Category | Tools |
|---|---|
| Language | Python 3.13 |
| Libraries | requests · csv · sys · time |
| APIs | ip-api.com REST API |
| Platform | Kali Linux · Windows 10 · VS Code |

---

## ⚖️ Legal & Ethical Notice

All scripts documented in this repository were developed for educational purposes as part of the
Swiss Cyber Institute Cybersecurity Specialist program. Scripts are intended for use in authorised
environments only. All work complies with Swiss law and ethical hacking standards.

---

## ⚖️ License

MIT — see [LICENSE](./LICENSE)
