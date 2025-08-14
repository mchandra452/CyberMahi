---
tags: [oscp, enumeration]
---
# Enumeration

## Tools & Syntax
- **enum4linux-ng** - `enum4linux-ng -A target`
- **smbclient** - `smbclient -L //<IP>`
- **rpcclient** - `rpcclient -U "" <IP>`
- **snmpwalk** - `snmpwalk -v2c -c public <IP>`
- **nmap scripts** - `nmap --script=smb-vuln* -p445 <IP>`

## Tips
- Always check anonymous logins.
- Leverage `nmap` scripts for deeper info.
- Look for default credentials on services.
