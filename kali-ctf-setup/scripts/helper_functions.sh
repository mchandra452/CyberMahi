#!/usr/bin/env bash
# Helper functions for colored output

GREEN="\e[32m"
RED="\e[31m"
BLUE="\e[34m"
RESET="\e[0m"

print_info() {
  echo -e "${BLUE}[+] $1${RESET}"
}

print_success() {
  echo -e "${GREEN}[*] $1${RESET}"
}

print_error() {
  echo -e "${RED}[-] $1${RESET}"
}
