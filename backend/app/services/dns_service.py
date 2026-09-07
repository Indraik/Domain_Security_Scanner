import logging
import dns.resolver
from app.config import Config

logger = logging.getLogger(__name__)


def get_dns_resolver():
    """Initializes and returns a configured DNS Resolver."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = Config.DNS_NAMESERVERS
    resolver.timeout = Config.DNS_TIMEOUT
    resolver.lifetime = Config.DNS_LIFETIME
    return resolver


def get_mx(domain: str) -> list[str]:
    """Resolves and returns MX exchange records for a domain."""
    resolver = get_dns_resolver()
    try:
        answers = resolver.resolve(domain, "MX")
        return [r.exchange.to_text().rstrip('.') for r in answers]
    except Exception as e:
        logger.warning(f"MX lookup failed for {domain}: {e}")
        return []


def get_txt(domain: str) -> list[str]:
    """Resolves and returns TXT records for a domain."""
    resolver = get_dns_resolver()
    records = []
    try:
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            records.append(txt)
    except Exception as e:
        logger.warning(f"TXT lookup failed for {domain}: {e}")
    return records


def get_dmarc(domain: str) -> list[str]:
    """Resolves and returns DMARC TXT records for _dmarc.<domain>."""
    resolver = get_dns_resolver()
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = []
        for rdata in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            records.append(txt)
        return records
    except Exception as e:
        logger.warning(f"DMARC lookup failed for {domain}: {e}")
        return []


def check_dnssec(domain: str) -> dict:
    """Checks whether DNSSEC records (DNSKEY) are present and active."""
    resolver = get_dns_resolver()
    try:
        answers = resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if answers.rrset:
            return {
                "status": "Enabled",
                "risk": "Low Risk",
                "message": "DNSSEC is enabled and DNS responses are cryptographically signed."
            }
        else:
            raise Exception("No DNSKEY records found")
    except Exception:
        return {
            "status": "Not Enabled",
            "risk": "Medium Risk",
            "message": "DNSSEC is not enabled or not publicly accessible."
        }
