# Kali CTF Setup

This directory contains scripts and package lists to prepare a fresh Kali Linux installation for Capture The Flag (CTF) competitions.

## Contents

- `setup.sh` – Main script that updates the system and installs tools listed in the package lists.
- `package-lists/` – Text files containing packages for APT, `pipx`, and Ruby gems.
- `scripts/` – Additional helper and post-install scripts.

## Default Tools

The package lists include commonly used utilities for CTF competitions, such as:

- **Enumeration:** nmap, masscan, rustscan, nikto, gobuster
- **Web:** sqlmap, burpsuite, wfuzz, xsser
- **Cracking:** hydra, john, hashcat
- **Binary/RE:** gdb, radare2, ghidra, apktool, dex2jar, ropgadget
- **Wireless:** aircrack-ng, reaver, kismet
- **Forensics:** binwalk, volatility, foremost
- **Utilities:** git, vim, tmux, zsh

Python tools like `pwntools`, `impacket`, `ropgadget`, and `scapy` are installed with `pipx`.

## Full Scanner Setup

On Kali Linux or Parrot OS, the `install-tools` function provisions a wide range of open-source scanners and utilities, including:

- nmap
- masscan
- rustscan
- nikto
- gobuster
- sqlmap
- wfuzz
- xsser
- hydra
- john
- hashcat
- gdb
- radare2
- ghidra
- apktool
- dex2jar
- ropgadget
- aircrack-ng
- reaver
- kismet
- binwalk
- volatility
- foremost
- git
- vim
- tmux
- zsh

To install the full suite, run:

```bash
bash ctf_codex_companion.sh install-tools
```

## Usage

1. **Review and modify package lists** in `package-lists/` to suit your needs.
2. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
3. **Log out and back in** or source your shell configuration (`source ~/.bashrc`) to apply changes.

## Troubleshooting

- **No sudo privileges:** The scripts rely on `sudo` to install packages. Run as root or obtain administrative access before executing them.
- **Non-Debian systems:** These scripts target Debian-based distributions like Kali and Parrot. On other systems, adapt the package manager commands and install equivalents manually.

## Disclaimer

Use these scripts responsibly and only on systems where you have explicit permission. Improper use of the installed tools may violate laws or terms of service.
