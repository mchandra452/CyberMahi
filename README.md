# CyberMahi

This repository contains utilities for CTF preparation. Use the `ctf_codex_companion.sh` script to ensure common scanners are available on your system.

## Supported Scanners
The script checks for and can install the following tools:

- nmap
- masscan
- rustscan
- gobuster
- nikto
- sqlmap
- wfuzz

## Installation
Run the companion script to automatically install any missing scanners. The script detects whether the host is based on Kali or Parrot using `/etc/os-release` and runs the appropriate update and install commands.

```bash
chmod +x ctf_codex_companion.sh
./ctf_codex_companion.sh
```

This will prompt the script to update package lists and install the above tools via `apt-get` or `parrot-upgrade` as needed.
