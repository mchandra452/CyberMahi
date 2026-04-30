"""Allowlist utilities for AgentShield Lab."""

# Define allowed commands for tool execution
ALLOWED_COMMANDS = ["ls", "cat"]


def is_allowed(command: str) -> bool:
    """Check if the given command is on the allowlist."""
    if not command:
        return False
    return command.split()[0] in ALLOWED_COMMANDS
