#!/usr/bin/env bash
# Companion script for installing common CTF scanners.

# List of tools required by the script. This list can be expanded as needed.
REQUIRED_TOOLS=(
  "nmap"
  "masscan"
  "rustscan"
  "gobuster"
  "nikto"
  "sqlmap"
  "wfuzz"
)

# Install the scanners based on the underlying distro.
install_scanners() {
  local packages=("$@")
  [[ ${#packages[@]} -eq 0 ]] && return

  # Determine if sudo is required
  if [[ $EUID -ne 0 ]]; then
    SUDO="sudo "
  else
    SUDO=""
  fi

  # Identify the distribution from /etc/os-release
  local distro
  distro=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

  case "$distro" in
    kali)
      ${SUDO}apt-get update && ${SUDO}apt-get install -y "${packages[@]}"
      ;;
    parrot|parrotos)
      ${SUDO}parrot-upgrade -y && ${SUDO}apt-get install -y "${packages[@]}"
      ;;
    *)
      ${SUDO}apt-get update && ${SUDO}apt-get install -y "${packages[@]}"
      ;;
  esac
}

# Check for missing dependencies and trigger installation if necessary.
check_deps() {
  local missing=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing tools: ${missing[*]}"
    install_scanners "${missing[@]}"
  else
    echo "All required tools are installed."
  fi
}

# Run dependency check if script executed directly.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  check_deps "$@"
fi
