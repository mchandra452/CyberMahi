"""Output filtering utilities for AgentShield Lab."""

def filter_output(output: str) -> str:
    """Mask sensitive keywords in the output string."""
    if not isinstance(output, str):
        return ""
    # Example sensitive keywords to mask
    sensitive_keywords = ["api_key", "password", "secret", "access_token"]
    redacted = output
    for keyword in sensitive_keywords:
        redacted = redacted.replace(keyword, "[REDACTED]")
    return redacted
