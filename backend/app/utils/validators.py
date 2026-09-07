import re
from urllib.parse import urlparse

# Regex pattern for valid domain names (RFC 1035 / RFC 1123)
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def sanitize_domain(domain_input: str) -> str:
    """
    Cleans domain input by stripping protocols (http/https),
    paths, ports, trailing slashes, and leading/trailing whitespace.
    """
    if not domain_input or not isinstance(domain_input, str):
        return ""
    
    cleaned = domain_input.strip().lower()
    
    # If the user included http:// or https://, parse the netloc
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = parsed.netloc or parsed.path
    
    # Remove paths, ports, or queries if present
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]
        
    return cleaned.strip()


def validate_domain(domain_input: str) -> tuple[bool, str]:
    """
    Validates the sanitized domain string.
    Returns (is_valid, sanitized_domain_or_error_message).
    """
    domain = sanitize_domain(domain_input)
    if not domain:
        return False, "Domain cannot be empty."
    
    if len(domain) > 253:
        return False, "Domain name is too long (maximum 253 characters)."
        
    if not DOMAIN_REGEX.match(domain):
        return False, f"'{domain}' is not a valid domain format."
        
    return True, domain
