# external-recon

MCP server for external reconnaissance. A client such as VS Code starts this process and talks to it over stdin and stdout. The server name is `external-recon`.

The tools in `external-recon.py` resolve DNS records, read SPF, DMARC, and DKIM data, try TCP connections to a list of ports, and run the system `whois` program.

## Prerequisites

- Python 3.11 or newer. Commands below were run with Python 3.12.3.
- `mcp` 1.x. `external-recon.py` imports `FastMCP` from `mcp.server.fastmcp`. `mcp` 1.30.0 requires Python >=3.10 and provides that module. `mcp` 2.x does not.
- `dnspython`, which provides `dns.resolver`. `dnspython` 2.9.2 requires Python >=3.11.
- The `whois` executable on `PATH` when you call `whois_lookup`. The Python packages do not install it.

## Install

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'mcp>=1,<2' dnspython
```

There is no separate build step.

## Run

With the virtual environment activated:

```bash
python external-recon.py
```

`external-recon.py` calls `mcp.run(transport='stdio')`. The process reads MCP messages on stdin and writes responses on stdout. It keeps running while stdin stays open.

This repository has no test suite. To check that the file parses:

```bash
python3 -m py_compile external-recon.py
```

## Usage

Point an MCP client at the virtual environment Python and `external-recon.py`. In VS Code `settings.json`, use absolute paths:

```json
{
  "mcp": {
    "servers": {
      "external-recon": {
        "command": "/absolute/path/to/this/repo/.venv/bin/python",
        "args": [
          "/absolute/path/to/this/repo/external-recon.py"
        ]
      }
    }
  }
}
```

Tools in `external-recon.py`:

- `setup_prompt(domainname)` returns text that asks the model to enumerate that domain and report IP addresses, subdomains, and email security.
- `dns_lookup(domain)` resolves A, MX, NS, TXT, and SOA records. Each record type is returned as a list of strings, or as an error string when resolution fails.
- `check_email_security(domain)` looks for an SPF TXT record (`v=spf1`), a DMARC TXT record at `_dmarc.<domain>` (`v=DMARC1`), and DKIM TXT records. DKIM selectors tried, in order, are `default`, `mail`, `email`, `selector1`, `selector2`, `k1`, and `dkim`. The first match sets `dkim_configured`, `dkim_selector`, and `dkim`.
- `scan_ports(target, ports)` checks TCP ports on `target`. An IPv4 dotted quad is used as the address. Any other value is resolved with `socket.gethostbyname`. `ports` is a comma-separated list. The default is `21,22,23,25,53,80,443,8080,8443`. Each connect uses a 1 second timeout. Open ports are labeled FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), HTTP (80), HTTPS (443), RDP (3389), HTTP-Alt (8080), or HTTPS-Alt (8443). Any other open port is labeled `unknown`.
- `whois_lookup(domain)` runs `whois` with a 30 second timeout. The result includes `raw_data` plus `registrar`, `creation_date`, and `expiration_date` when those lines are present in the command output.

## Layout

- `external-recon.py` is the MCP server.
- `README.md` is this file.

No license file is included.
