# BlackMagic NetHunt — Network Recon (bm_nethunt)

## Description

Wraps the BlackMagic `nethunt.bm` sysadmin module for use in msfconsole.
Performs nmap port scanning, traceroute with per-hop whois annotation, HTTP
probing, and DNS inspection. Results are reported into the MSF database when
JSON_OUTPUT is enabled.

## Requirements

- BlackMagic sysadmin toolkit: `~/apps/chloe/modules/sysadmin/nethunt.bm`
- Tools: `nmap`, `traceroute`, `whois`, `xh` (install via `bmpkg install <tool>`)

## Modes

| MODE | Description |
|------|-------------|
| scan | nmap quick scan — open ports + service versions |
| scan-full | nmap all 65535 ports |
| trace | traceroute with per-hop whois org lookup |
| whois | whois record for host |
| http | HTTP request via xh (pretty-printed) |
| local | local interface / route / open port info |

## Usage

```
msf > use auxiliary/scanner/recon/bm_nethunt
msf auxiliary(bm_nethunt) > set RHOST 192.168.1.1
msf auxiliary(bm_nethunt) > set MODE scan
msf auxiliary(bm_nethunt) > run

msf auxiliary(bm_nethunt) > set MODE trace
msf auxiliary(bm_nethunt) > run

msf auxiliary(bm_nethunt) > set MODE local
msf auxiliary(bm_nethunt) > run
```

With JSON reporting into MSF database:
```
msf auxiliary(bm_nethunt) > set JSON_OUTPUT true
msf auxiliary(bm_nethunt) > run
```

## Environment Setup

No vulnerable environment needed — this is a local recon tool wrapping nmap.
Ensure nmap is installed: `bmpkg install nmap` or `pkg install nmap`.
