#!/usr/bin/env bash
# CTF Codex Companion - Bash edition
# Simple helpers for CTF players
set -euo pipefail

# Tools required for features in this script
REQUIRED_TOOLS=(nmap)

check_deps() {
  local missing=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done
  if (( ${#missing[@]} )); then
    echo "Installing missing tools: ${missing[*]}"
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get update -y
      sudo apt-get install -y "${missing[@]}"
    else
      echo "Please install: ${missing[*]}" >&2
      return 1
    fi
  fi
}

usage() {
  cat <<USAGE
CTF Codex Companion (bash)
Usage: $0 <command> [args]

Commands:
  recon <target>     Run a tiny nmap scan
  payload <vuln>     Print common payload (sqli, xss, ssti)
  tools <desc>       Suggest tools for a challenge description
  flag <candidate>   Validate flag format
  snack              Show drink/snack pairings
USAGE
}

recon() {
  nmap -sV -Pn "$1"
}

declare -A PAYLOADS=(
  [sqli]="' OR '1'='1' -- "
  [xss]='<script>alert(1)</script>'
  [ssti]='{{7*7}}'
)

payload() {
  local p=${PAYLOADS[$1]:-}
  if [[ -n "$p" ]]; then
    echo "$p"
  else
    echo "Unknown vulnerability type" >&2
    return 1
  fi
}

classify() {
  local desc=${1,,}
  if [[ $desc == *web* ]]; then echo web; return; fi
  if [[ $desc == *re* ]]; then echo re; return; fi
  if [[ $desc == *pwn* ]]; then echo pwn; return; fi
  if [[ $desc == *crypto* ]]; then echo crypto; return; fi
  echo misc
}

suggest_tools() {
  case $(classify "$1") in
    web) echo "BurpSuite, sqlmap, ffuf";;
    re) echo "Ghidra, radare2";;
    pwn) echo "pwntools, gdb";;
    crypto) echo "sagemath, RsaCtfTool";;
    *) echo "Try common recon tools";;
  esac
}

validate_flag() {
  if [[ $1 =~ ^[A-Za-z0-9_]+\{.+\}$ ]]; then
    echo "Looks like a flag!"
  else
    echo "Nope, flag format mismatch"
    return 1
  fi
}

snack() {
  echo "coffee + dark chocolate"
  echo "green tea + almonds"
  echo "water + fruit"
}

main() {
  if [[ $# -lt 1 || $1 == -h || $1 == --help ]]; then
    usage; return 0
  fi

  check_deps

  case $1 in
    recon)
      shift
      recon "$@";;
    payload)
      shift
      payload "$@";;
    tools)
      shift
      suggest_tools "$*";;
    flag)
      shift
      validate_flag "$@";;
    snack)
      snack;;
    *)
      usage
      return 1;;
  esac
}

main "$@"
