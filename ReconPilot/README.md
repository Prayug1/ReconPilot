# ReconPilot — Automated Reconnaissance Framework

ReconPilot is a Qt-based desktop reconnaissance framework for authorized security assessments, bug-bounty reconnaissance, CTF/lab environments, and attack-surface analysis. It combines common reconnaissance tools with native Python checks and presents the results in one interface with live logs, per-module tables, saved artifacts, and an HTML report.

> **Authorization required:** ReconPilot is intended only for systems you own or are explicitly authorized to test. The application requires an authorization/scope confirmation before a scan starts.

<img width="1909" height="947" alt="ReconPilot interface" src="https://github.com/user-attachments/assets/37571c2e-93c6-4dd4-b744-48c164cef1d1" />

## Highlights

- Desktop GUI built with **PySide6 / Qt 6**
- Mandatory live-host validation before the remaining scan workflow runs
- Separate **Bug Bounty** and **Controlled / CTF** scan profiles
- Default phased scan order or custom module selection/order
- Real-time module state, progress, and console logging
- Structured JSON/text artifacts plus a consolidated `report.html`
- Local **Ollama AI Advisor** that can review a generated ReconPilot report and suggest evidence-based next steps
- No cloud AI SDK or API key is required

## Scan Profiles

### Bug Bounty Mode

The default profile is designed for broad external reconnaissance. Its default module order is:

1. HTTP security headers
2. WAF detection (`wafw00f`)
3. WhatWeb fingerprinting
4. SSL/TLS certificate enumeration
5. DNS enumeration
6. Subdomain enumeration (`subfinder`)
7. HTTP probing (`httpx-toolkit`)
8. Nmap service discovery
9. URL harvesting
10. JavaScript collection
11. JavaScript secret scanning
12. Nuclei vulnerability scanning

The URL harvester combines built-in passive collectors for the Wayback Machine, urlscan.io, and AlienVault OTX with optional/CLI-backed sources such as `gau`, `waybackurls`, and `gospider`. URLs are filtered to the requested target domain/subdomains and deduplicated while preserving source attribution.

### Controlled / CTF Mode

The Controlled / CTF profile is intentionally more active and is intended for labs, CTFs, and other explicitly authorized targets. Its default workflow includes:

1. HTTP security headers
2. WAF detection
3. WhatWeb fingerprinting
4. SSL/TLS certificate enumeration
5. Directory enumeration with `feroxbuster`
6. Host-header subdomain/vhost fuzzing with `ffuf`
7. Nmap service discovery
8. Active URL crawling with `gospider`
9. JavaScript collection
10. JavaScript secret scanning
11. Nuclei vulnerability scanning

CTF directory enumeration uses the DirBuster medium wordlist when available and falls back to a matching SecLists web-content wordlist. CTF subdomain/vhost fuzzing uses SecLists DNS wordlists and is skipped for IP-literal targets.

## Modules

| Module | Purpose | Main dependency |
|---|---|---|
| Live Host | DNS resolution, ICMP probe, HTTP fallback | `ping`, `requests` |
| HTTP Headers | Security-header posture | `requests`, `urllib3` |
| WAF Detection | WAF/firewall fingerprinting with scheme/port fallback | `wafw00f` |
| WhatWeb | Web technology/CMS/framework fingerprinting | `whatweb` |
| SSL/TLS Cert | TLS handshake and X.509 certificate parsing | `cryptography` |
| DNS Enum | A/AAAA/MX/NS/TXT/security-related DNS records, SPF/DMARC posture | `dnspython` |
| Subdomain Enum | Passive subdomain discovery | `subfinder` |
| HTTP Probe | Live URL, status, title, and technology detection | `httpx-toolkit` |
| Nmap Scan | Ports, services, versions, OS information where available | `nmap` |
| Directory Enum | Active content discovery for CTF/lab targets | `feroxbuster`, wordlist |
| Subdomain Bruteforce | Host-header vhost/subdomain fuzzing | `ffuf`, SecLists |
| URL Harvest | Passive URL collection or active CTF crawl | built-ins, `gospider`, optional `gau`/`waybackurls` |
| JS Collector | Discover and download JavaScript assets | `requests`, `beautifulsoup4` |
| JS Secrets | Scan downloaded JS for high-risk secret patterns | Python standard library |
| Nuclei Scan | Template-based vulnerability scanning | `nuclei` |

## Requirements

### Python

ReconPilot requires **Python 3.10 or newer**. The direct Python dependencies are maintained in `requirements.txt`:

- PySide6
- requests
- urllib3
- beautifulsoup4
- dnspython
- cryptography

### External tools

The current code can use the following external commands:

- `ping` (`iputils-ping` on Debian-family Linux)
- `nmap`
- `subfinder`
- `httpx-toolkit`
- `whatweb`
- `wafw00f`
- `nuclei`
- `gospider`
- `feroxbuster`
- `ffuf`
- SecLists wordlists

Optional URL-harvest boosters:

- `gau`
- `waybackurls`

`install.sh` checks/installs these where possible. On systems where a Kali package is not available, it uses Go or pip fallbacks for supported tools.

## Installation

### Recommended: installer script

The installer is designed for Kali, Debian, and Ubuntu-style systems. It installs Python dependencies from the same `requirements.txt` used by the project, installs/checks the current CLI dependencies, adds user/Go binary directories to your shell PATH, updates Nuclei templates, and performs a final dependency check.

```bash
chmod +x install.sh
./install.sh
```

Then launch ReconPilot:

```bash
python3 main.py
```

If the installer added a command to your PATH and the current shell has not picked it up yet:

```bash
source ~/.zshrc   # Kali default
# or
source ~/.bashrc
```

### Manual Python setup

A virtual environment is the cleanest manual option:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

On a PEP 668-managed Kali/Debian Python installation, a user-site install can also be used:

```bash
python3 -m pip install --user --break-system-packages -r requirements.txt
python3 main.py
```

You must still install the external CLI tools required by the modules you want to run.

## AI Advisor (Optional)

ReconPilot includes an optional local AI Advisor. It reads the generated `report.html`, strips the HTML markup, and sends the report text to a locally running Ollama server using the existing `requests` dependency.

Default settings:

```text
Provider:  ollama
Base URL:  http://127.0.0.1:11434
Model:     gemma3:1b
```

Settings can be changed in **File → AI Advisor Settings…** and are stored in:

```text
~/.config/reconpilot/config.json
```

Environment-variable fallbacks are also supported:

```text
RECONPILOT_AI_PROVIDER
OLLAMA_BASE_URL
OLLAMA_MODEL
```

Ollama itself is not a Python requirement and is not required for normal scanning. Install/run Ollama separately and make sure the configured model is available before using AI Advisor.

## Usage

```bash
python3 main.py
```

Typical workflow:

1. Enter a target domain, IP address, or URL.
2. Choose **Bug Bounty** or **Controlled / CTF** mode.
3. Use the default phased workflow or enable custom module selection/order.
4. Confirm that you are authorized and that the target is in scope.
5. Start the scan and monitor the live module/status output.
6. Review findings in the categorized result tabs.
7. Open the generated HTML report or run the optional AI Advisor against it.

## Output

ReconPilot stores the current scan under:

```text
output/<sanitized-target>/
```

A new scan of the same target **clears and replaces the previous artifacts for that target** rather than creating timestamped subdirectories.

Core output files include:

```text
results.json          Consolidated structured results
report.html           Consolidated HTML report
scan.log              Full scan/module console transcript
```

Depending on the selected modules, the target directory can also contain artifacts such as:

```text
nmap.xml
subdomains.txt
http_probe.jsonl
live_urls.txt
whatweb.jsonl
ssl_cert.json
nuclei.jsonl
nuclei_targets.txt
all_urls.txt
all_urls_with_sources.json
url_harvest_summary.json
url_harvest_sources/
feroxbuster/
feroxbuster_results.json
feroxbuster_urls.txt
ffuf_subdomain_fuzz.json
ffuf_subdomain_fuzz_hosts.txt
js_files.txt
js_files_with_sources.json
js_download_manifest.json
js_download_failures.json
js/downloaded/
js_secrets.json
ai_advisor.md
ai_advisor.json
```

The exact set depends on scan mode, selected modules, target behavior, and which tools are available.

## Project Structure

```text
reconpilot/
├── main.py
├── install.sh
├── requirements.txt
├── LICENSE
├── README.md
├── core/
│   └── scan_manager.py
├── modules/
│   ├── ai_advisor.py
│   ├── dir_enum.py
│   ├── dns_enum.py
│   ├── http_headers.py
│   ├── http_probe.py
│   ├── js_collector.py
│   ├── js_secrets.py
│   ├── live_host.py
│   ├── nmap_scan.py
│   ├── nuclei_scan.py
│   ├── ssl_cert.py
│   ├── subdomain_fuzz.py
│   ├── subdomain_scan.py
│   ├── url_harvest.py
│   ├── waf_scan.py
│   └── whatweb_scan.py
├── ui/
│   └── main_window.py
├── utils/
│   ├── ai_config.py
│   ├── logger.py
│   ├── parser.py
│   ├── process_control.py
│   ├── reporter.py
│   └── runtime.py
└── resources/
    └── ai_advisor_overrides/
```

## Notes

- The live-host check always runs first. If ReconPilot considers the target unreachable, dependent scanning is stopped.
- Missing external tools affect only the modules that require them; the GUI exposes tool availability in its Tool Status panel.
- Several network operations intentionally rely on the underlying tool/server behavior rather than imposing a short ReconPilot-level timeout. Use **Stop Scan** to cancel an active workflow.
- Nuclei templates should be kept current with `nuclei -update-templates`.

## Legal / Ethical Use

ReconPilot is intended for authorized security testing, security research, education, bug-bounty programs within scope, and controlled lab/CTF environments. You are responsible for obtaining permission and complying with applicable laws, program rules, and target scope.

## Author

**Prayug Bijukchhe**

## License

ReconPilot is released under the **MIT License**. See [`LICENSE`](LICENSE).

## Contributing

Contributions, bug reports, documentation improvements, and feature suggestions are welcome. When adding or changing a module, please also update `requirements.txt`, `install.sh`, and this README if the change introduces a new Python package, external CLI tool, wordlist, runtime service, or output artifact.
