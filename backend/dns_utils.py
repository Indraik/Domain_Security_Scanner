"""
Backward-compatibility facade for dns_utils.
Re-exports modularized domain services from app.services.
"""

from app.services.dns_service import (
    get_mx,
    get_txt,
    get_dmarc,
    check_dnssec,
)
from app.services.email_security import (
    analyze_spf,
    explain_spf_risk,
    analyze_dmarc,
    explain_dmarc_risk,
    get_spf_score,
    get_dmarc_score,
    classify_txt,
    calculate_email_security_score,
)
from app.services.web_security import (
    get_web_info,
    check_https,
)
from app.services.port_scanner import (
    scan_ports,
)

__all__ = [
    "get_mx",
    "get_txt",
    "get_dmarc",
    "check_dnssec",
    "analyze_spf",
    "explain_spf_risk",
    "analyze_dmarc",
    "explain_dmarc_risk",
    "get_spf_score",
    "get_dmarc_score",
    "classify_txt",
    "calculate_email_security_score",
    "get_web_info",
    "check_https",
    "scan_ports",
]
