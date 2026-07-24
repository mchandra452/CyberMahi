#!/usr/bin/env bash
# Additional steps, e.g., configuring shells, shortcuts, or environment variables.

# Enable colored prompts
cat <<'BASHRC' >> ~/.bashrc
export PS1="\[\e[1;32m\]\u@\h:\w\$ \[\e[0m\]"
BASHRC

# Setup tmux config
cat <<'EOF_TMUX' > ~/.tmux.conf
setw -g mode-keys vi
set -g history-limit 10000
EOF_TMUX

print_success "Post-install configuration complete."
