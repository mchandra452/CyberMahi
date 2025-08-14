---
tags: [oscp, privesc]
---
# Privilege Escalation

## Tools & Syntax
- **linpeas** - `./linpeas.sh`
- **linenum** - `./linenum.sh`
- **sudo** - `sudo -l`
- **getcap** - `getcap -r / 2>/dev/null`
- **winPEAS** - `winpeas.exe`

## Tips
- Check `/etc/sudoers` for misconfigured entries.
- Search for writable cron jobs or timers.
- Review capabilities and SUID binaries.
