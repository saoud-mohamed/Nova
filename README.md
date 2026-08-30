# NOVA

### Web Security Fuzzing Framework

**NOVA** is a modular web security fuzzing framework designed for security research, authorized penetration testing, CTFs, and vulnerability discovery.

```text
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
████╗  ██║██╔═══██╗██║   ██║██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚════╝  ╚═╝  ╚═╝
```

> DISCOVER • FUZZ • ANALYZE • DETECT

---

## Features

NOVA currently supports:

* Path discovery
* GET parameter discovery
* POST parameter discovery
* JSON parameter discovery
* Subdomain discovery
* Recursive crawling
* Payload-based fuzzing
* XSS response analysis
* SQL Injection response analysis
* SSTI response analysis
* LFI response analysis
* Command Injection response analysis
* XXE detection
* Response similarity analysis
* Dynamic-content normalization
* Response fingerprinting
* Baseline calibration
* Adaptive request throttling
* Rate limiting
* Finding scoring
* Confidence levels
* Rich terminal interface

---

## Architecture

```text
                    ┌─────────────────┐
                    │      NOVA       │
                    │      CLI        │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    Requester    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  Nova Engine    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
          Discovery       Analysis       Results
              │              │              │
       ┌──────┼──────┐   ┌───┼────┐         │
       │      │      │   │   │    │         │
      Path   Param  Sub  XSS SQLi SSTI       │
       │      │      │   │   │    │         │
       └──────┴──────┴───┴───┴────┴─────────┘
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Nova.git
cd Nova
```

Create a virtual environment:

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install NOVA:

```bash
pip install -e .
```

Verify:

```bash
nova -h
```

---

## Usage

### Path Discovery

```bash
nova -u http://127.0.0.1:8000/FUZZ -w wordlists/paths.txt -m path
```

### GET Parameter Discovery

```bash
nova -u "http://127.0.0.1:8000/search" \
    -w wordlists/parameters.txt \
    -m param
```

Example:

```bash
nova -u "http://127.0.0.1:8000/search?q=test" \
    -w wordlists/parameters.txt \
    -m param
```

### POST Parameter Discovery

```bash
nova -u http://127.0.0.1:8000/login \
    -w wordlists/parameters.txt \
    -m post
```

### JSON Parameter Discovery

```bash
nova -u http://127.0.0.1:8000/api \
    -w wordlists/parameters.txt \
    -m json
```

### Subdomain Discovery

```bash
nova -u https://example.com \
    -w wordlists/subdomains.txt \
    -m subdomain
```

### Recursive Discovery

```bash
nova -u http://127.0.0.1:8000 \
    -w wordlists/paths.txt \
    -m recursive \
    --max-pages 50
```

### Payload Fuzzing

Example XSS testing:

```bash
nova -u "http://127.0.0.1:8000/search?q=test" \
    -w wordlists/xss.txt \
    -m payload \
    -t xss \
    -p q
```

SQL Injection response analysis:

```bash
nova -u "http://127.0.0.1:8000/user?id=1" \
    -w wordlists/sqli.txt \
    -m payload \
    -t sqli \
    -p id
```

SSTI:

```bash
nova -u "http://127.0.0.1:8000/page?name=test" \
    -w wordlists/ssti.txt \
    -m payload \
    -t ssti \
    -p name
```

LFI:

```bash
nova -u "http://127.0.0.1:8000/file?page=test" \
    -w wordlists/lfi.txt \
    -m payload \
    -t lfi \
    -p page
```

Command injection:

```bash
nova -u "http://127.0.0.1:8000/ping?host=test" \
    -w wordlists/command.txt \
    -m payload \
    -t command \
    -p host
```

---

## Request Controls

Timeout:

```bash
--timeout 10
```

Rate limiting:

```bash
--rate 5
```

Custom parameter value:

```bash
--value nova
```

For recursive scanning:

```bash
--max-pages 100
```

---

## Finding Model

NOVA uses three confidence levels:

```text
HIGH
MEDIUM
LOW
```

Findings contain information such as:

```text
TYPE
VALUE
URL
STATUS
SCORE
CONFIDENCE
SIMILARITY
REASONS
METADATA
```

Example:

```text
CONFIDENCE   TYPE          VALUE       STATUS   SCORE
HIGH         payload:sqli  payload     500      90.0
MEDIUM       payload:xss   payload     200      74.2
LOW          path          admin       200      41.7
```

---

## Response Analysis

NOVA establishes a baseline response before fuzzing.

```text
Target
  │
  ▼
Baseline Request
  │
  ▼
Normalize Dynamic Content
  │
  ▼
Fingerprint
  │
  ▼
Fuzz Request
  │
  ▼
Compare Responses
  │
  ├── Status
  ├── Length
  ├── Words
  ├── Lines
  └── Similarity
        │
        ▼
      Score
        │
        ▼
     Finding
```

This helps reduce obvious false positives caused by dynamic content and small response changes.

---

## SQL Injection Detection

NOVA's SQLi analyzer currently focuses on **response-based database error signatures**.

It can recognize common signatures associated with:

* MySQL
* PostgreSQL
* Microsoft SQL Server
* Oracle
* SQLite
* Generic SQL errors

Example evidence categories:

```text
database_error_signature
explicit_sql_error
generic_sql_error_signature
```

NOVA does not automatically exploit SQL injection vulnerabilities.

---

## Project Structure

```text
Nova/
│
├── nova_cli.py
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
│
├── nova/
│   │
│   ├── core/
│   │   ├── requester.py
│   │   ├── response.py
│   │   ├── engine.py
│   │   ├── baseline.py
│   │   ├── results.py
│   │   ├── fingerprint.py
│   │   ├── similarity.py
│   │   ├── dynamic.py
│   │   ├── rate_limiter.py
│   │   ├── adaptive.py
│   │   └── url_normalizer.py
│   │
│   ├── discovery/
│   │   ├── path.py
│   │   ├── parameter.py
│   │   ├── post_parameter.py
│   │   ├── json_parameter.py
│   │   ├── subdomain.py
│   │   ├── recursive.py
│   │   ├── pipeline.py
│   │   ├── payload.py
│   │   └── xxe.py
│   │
│   ├── analyzers/
│   │   ├── xss.py
│   │   ├── sqli.py
│   │   ├── ssti.py
│   │   ├── lfi.py
│   │   └── command.py
│   │
│   └── utils/
│       └── wordlist.py
│
└── wordlists/
    ├── paths.txt
    ├── parameters.txt
    ├── subdomains.txt
    ├── xss.txt
    ├── sqli.txt
    ├── ssti.txt
    ├── lfi.txt
    └── command.txt
```

---

## Development Status

### NOVA v6.0.0

Current modules:

```text
[✓] Requester
[✓] Rate Limiter
[✓] Adaptive Controller
[✓] Response Model
[✓] Baseline
[✓] Dynamic Content Normalization
[✓] Fingerprinting
[✓] Similarity Engine
[✓] Result Engine
[✓] Nova Engine
[✓] Path Discovery
[✓] GET Parameter Discovery
[✓] POST Parameter Discovery
[✓] JSON Parameter Discovery
[✓] Subdomain Discovery
[✓] Recursive Discovery
[✓] Payload Discovery
[✓] XSS Analyzer
[✓] SQLi Analyzer
[✓] SSTI Analyzer
[✓] LFI Analyzer
[✓] Command Analyzer
[✓] XXE Discovery
[✓] Rich CLI
[✓] Packaging
[ ] Advanced parameter intelligence
[ ] Improved crawling
[ ] Advanced response clustering
[ ] HTTP method fuzzing
[ ] Export formats
[ ] Advanced SQLi detection
```

---

## Security & Authorization

NOVA is intended for:

* Your own applications
* Local laboratories
* CTF environments
* Authorized penetration tests
* Security research with permission

Only scan systems you are authorized to test.

---

## License

MIT License.

Copyright (c) 2026 Nova Project
