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

As of **April 30, 2026**, the `install-tools` function is designed to pull the latest package versions available from your distro repositories (`apt`) and `pipx`.

Open-source tools provisioned include:

- **Network & recon:** nmap, masscan, rustscan, amass
- **Web scanning/fuzzing:** nikto, gobuster, feroxbuster, ffuf, wfuzz, nuclei, whatweb, xsser, sqlmap
- **Credential/cracking:** hydra, john, hashcat
- **Binary/mobile RE:** gdb, radare2, ghidra, apktool, dex2jar, ropgadget
- **Wireless:** aircrack-ng, reaver, kismet
- **Forensics:** binwalk, volatility, foremost
- **Wordlists & support:** seclists, git, vim, tmux, zsh

Python tooling via `pipx` includes pwntools, impacket, scapy, ropgadget, dirsearch, and supporting libraries.

To install the full suite, run:

```bash
bash ctf_codex_companion.sh install-tools
```

or if the script is executable:

```bash
./ctf_codex_companion.sh install-tools
```

To verify installed versions afterwards:

```bash
nmap --version
rustscan --version
sqlmap --version
nuclei -version
ffuf -V
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

- **No sudo privileges:** The scripts rely on `sudo` for `apt` installs. If `sudo` is unavailable, run as root, ask an administrator to pre-install packages, or comment out `apt` steps and run only user-space `pipx` installs.
- **Non-Debian systems:** These scripts target Debian-based distributions like Kali and Parrot. For Arch/Fedora/macOS, replace `apt` commands with your package manager equivalents and keep the `pipx` section for Python tools.

## Disclaimer

Use these scripts responsibly and only on systems where you have explicit permission. Improper use of the installed tools may violate laws or terms of service.
