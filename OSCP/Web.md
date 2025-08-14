---
tags: [oscp, web]
---
# Web

## Tools & Syntax
- **gobuster** - `gobuster dir -u http://target/ -w wordlist.txt`
- **wfuzz** - `wfuzz -c -z file,wordlist.txt --hc 404 http://target/FUZZ`
- **sqlmap** - `sqlmap -u "http://target/page.php?id=1" --batch --dump`
- **nikto** - `nikto -h http://target`
- **wpscan** - `wpscan --url http://target --enumerate u,plugins`

## Tips
- Use `--proxy` options to route through Burp.
- Customize wordlists for targeted directories.
- Always scan for known CVEs and misconfigurations.
