# Kali CTF Setup

This directory contains scripts and package lists to prepare a fresh Kali Linux installation for Capture The Flag (CTF) competitions.

## Contents

- `setup.sh` – Main script that updates the system and installs tools listed in the package lists.
- `package-lists/` – Text files containing packages for APT, `pipx`, and Ruby gems.
- `scripts/` – Additional helper and post-install scripts.

## Usage

1. **Review and modify package lists** in `package-lists/` to suit your needs.
2. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```
3. **Log out and back in** or source your shell configuration (`source ~/.bashrc`) to apply changes.

## Disclaimer

Use these scripts responsibly and only on systems where you have explicit permission. Improper use of the installed tools may violate laws or terms of service.
