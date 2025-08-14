---
tags: [oscp, recon]
---
# Recon

## Tools & Syntax
- **nmap** - `nmap -sC -sV -oA recon target`
- **masscan** - `masscan -p1-65535 --rate=2000 target`
- **whatweb** - `whatweb -v target`
- **whois** - `whois target.com`

## Tips
- Run `nmap` with `-Pn` if ICMP is blocked.
- Use multiple scanners to compare results.
- Save outputs (`-oA`) for later parsing.
