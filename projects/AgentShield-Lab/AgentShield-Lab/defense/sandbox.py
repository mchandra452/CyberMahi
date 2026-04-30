"""Simple sandbox for executing whitelisted commands."""
import subprocess
from typing import List

# Allowed commands (whitelist). Only these commands can be executed.
ALLOWED_COMMANDS: List[str] = ["ls", "cat"]


def safe_exec(command: str) -> str:
    """Execute a command if it is whitelisted.

    Args:
        command: The shell command to execute.

    Returns:
        The output of the command or a blocked message.
    """
    if not command:
        return "No command provided"
    parts = command.split()
    if not parts or parts[0] not in ALLOWED_COMMANDS:
        return "Blocked: Command not allowed"
    try:
        result = subprocess.run(parts, capture_output=True, text=True, timeout=5)
        return result.stdout.strip() or result.stderr.strip()
    except Exception as e:
        return f"Error executing command: {e}"
