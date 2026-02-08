# Wayfinder v4.0

**Bug Bounty Subdomain Enumeration Tool (Parallel Edition)**

Wayfinder aggregates subdomains from 8 sources simultaneously, giving you broader coverage than any single tool alone.

**Sources:** VirusTotal, SecurityTrails, crt.sh, Shodan, Chaos, URLScan, AlienVault OTX, Subfinder

---

## Features

- **Parallel Execution** - All 8 API sources queried at the same time
- **Subdomain Enumeration** - Single domain or batch mode from a list
- **Domain Acquisition** - Discover associated/related domains via SecurityTrails + OTX
- **IP Enumeration** - CIDR and IP discovery via SecurityTrails + Shodan SSL
- **Subdomain Expansion** - Generate and bruteforce permutations with alterx + shuffledns
- **Live Check** - Verify which subdomains are actually alive with httpx

---

## Installation

### Step 1: Clone the repo

```bash
git clone https://github.com/omar-secdown/wayfinder.git
cd wayfinder
```

### Step 2: Install Python dependencies

```bash
pip install -r requirements.txt
```

> If you get `externally-managed-environment` error (Debian/Ubuntu/Kali):
> ```bash
> pip install --break-system-packages -r requirements.txt
> ```

### Step 3: Install Go tools

Make sure [Go](https://go.dev/doc/install) is installed, then run:

```bash
chmod +x setup.sh
./setup.sh
```

This installs: `subfinder`, `httpx`, `alterx`, `shuffledns`, `anew`, and the Shodan CLI.

Or install them manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/tomnomnom/anew@latest
pip install shodan --break-system-packages
```

### Step 4: Configure API keys

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```
OTX_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CHAOS_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

**Where to get the keys:**

| Service | Sign Up |
|---------|---------|
| AlienVault OTX | https://otx.alienvault.com |
| SecurityTrails | https://securitytrails.com |
| VirusTotal | https://virustotal.com |
| Chaos (ProjectDiscovery) | https://chaos.projectdiscovery.io |
| URLScan.io | https://urlscan.io |

### Step 5: Configure Shodan (optional)

```bash
shodan init YOUR_SHODAN_API_KEY
```

### Step 6: Validate setup

```bash
python3 config.py
```

This checks all API keys, tools, and required files are properly configured.

---

## Usage

### Basic subdomain enumeration

```bash
python3 main.py -u example.com
```

### Batch mode (multiple domains)

```bash
python3 main.py -l domains.txt
```

### Check for live subdomains

```bash
python3 main.py -u example.com -live
```

### Subdomain expansion (alterx + shuffledns)

```bash
python3 main.py -u example.com -expand
```

### Full scan with expansion + live check

```bash
python3 main.py -l domains.txt -expand -live
```

### IP enumeration

```bash
python3 main.py -ips-d example.com
python3 main.py -ips-l targets.txt
```

### Subdomain + IP enumeration combined

```bash
python3 main.py -ips-enum-d example.com
python3 main.py -ips-enum-d example.com -live
```

### Domain acquisition (find related domains)

```bash
python3 main.py -acq example.com
python3 main.py -acq example.com -email abbvie,caterpillar
```

### Acquisition + enumeration

```bash
python3 main.py -acq-enum example.com -live -pd 5 -expand
```

### Verbose mode (debug output)

```bash
python3 main.py -u example.com -v
```

### Parallel domain processing

```bash
python3 main.py -l domains.txt -pd 5
```

---

## Output Structure

```
output/
|-- quick_results/              (Single domain: -u)
|   +-- example.com/
|       |-- subdomains.txt
|       |-- live_subdomains.txt
|       |-- all_in_one.txt           (if -expand)
|       +-- live_all_in_one.txt      (if -expand -live)
|
|-- scans/                      (Batch scans: -l, -acq-enum)
|   +-- 2026-01-05_example.com/
|
|-- acquisition/                (Acquisition: -acq)
|   +-- example.com_acquisition.txt
|
+-- ips/                        (IP enumeration)
    +-- ips_for_example.com_05_01.txt
```

---

## All Options

| Flag | Description |
|------|-------------|
| `-u DOMAIN` | Single target domain |
| `-l FILE` | File with list of domains |
| `-live` | Check for live subdomains (httpx) |
| `-expand` | Run subdomain expansion (alterx + shuffledns) |
| `-pd N` | Parallel domain count (default: 3) |
| `-v` | Verbose/debug output |
| `-ips-d DOMAIN` | IP enumeration for single domain |
| `-ips-l FILE` | IP enumeration for domain list |
| `-ips-enum-d DOMAIN` | Subdomain + IP enumeration |
| `-ips-enum-l FILE` | Subdomain + IP enumeration for list |
| `-acq DOMAIN` | Find associated domains |
| `-acq-enum DOMAIN` | Acquisition + subdomain enumeration |
| `-email DOMAINS` | Email domain filters for acquisition |
