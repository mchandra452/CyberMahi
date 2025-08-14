#!/usr/bin/env bash
# Simple setup script to prepare Kali for CTF events.
# Use responsibly and only with permission in authorized contexts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/scripts/helper_functions.sh"

print_info "Updating system..."
sudo apt update && sudo apt full-upgrade -y

print_info "Installing packages from apt.txt..."
xargs -a "${SCRIPT_DIR}/package-lists/apt.txt" sudo apt install -y

print_info "Installing Python packages from pip.txt..."
pipx install --force $(cat "${SCRIPT_DIR}/package-lists/pip.txt")

if [ -f "${SCRIPT_DIR}/package-lists/gem.txt" ]; then
  print_info "Installing Ruby gems from gem.txt..."
  sudo gem install $(tr '\n' ' ' < "${SCRIPT_DIR}/package-lists/gem.txt")
fi

if [ -f "${SCRIPT_DIR}/scripts/post_install.sh" ]; then
  print_info "Running post-install tasks..."
  bash "${SCRIPT_DIR}/scripts/post_install.sh"
fi

print_success "Kali CTF setup complete!"
