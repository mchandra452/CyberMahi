"""Input filtering utilities for AgentShield Lab."""
import re


def sanitize_prompt(prompt: str) -> str:
    """Perform basic sanitization on the user prompt.

    - Normalizes whitespace
    - Removes null bytes
    """
    if not isinstance(prompt, str):
        return ""
    sanitized = re.sub(r"[\r\n\t]+", " ", prompt)
    sanitized = sanitized.replace("\x00", "")
    return sanitized.strip()


def contains_blocked_pattern(prompt: str) -> bool:
    """Check if the prompt contains any explicitly blocked patterns."""
    blocked_patterns = ["<script>", "</script>", "drop table", "shutdown"]
    lower_prompt = prompt.lower()
    return any(p in lower_prompt for p in blocked_patterns)
