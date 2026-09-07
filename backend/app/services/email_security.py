"""
Email security policy evaluation service:
Handles SPF, DMARC, DKIM classification, risk scoring, and security metrics.
"""


def analyze_spf(txt_records: list[str]) -> str:
    """Analyzes TXT records and determines SPF policy enforcement strength."""
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            if "-all" in record:
                return "Strong"
            elif "~all" in record:
                return "SoftFail"
            else:
                return "Weak"
    return "Missing"


def explain_spf_risk(spf_status: str) -> dict:
    """Returns human-readable explanation and recommendations for SPF status."""
    if spf_status == "Strong":
        return {
            "level": "Low Risk",
            "message": "SPF strictly blocks unauthorized mail servers (-all).",
            "recommendation": "No action required."
        }
    elif spf_status == "SoftFail":
        return {
            "level": "Medium Risk",
            "message": "Unauthorized senders are flagged (~all) but not blocked.",
            "recommendation": "Transition '~all' to hard fail '-all' once all sending sources are verified."
        }
    elif spf_status == "Weak":
        return {
            "level": "High Risk",
            "message": "SPF record exists but does not restrict unauthorized senders (+all or ?all).",
            "recommendation": "Define permitted sending servers and enforce '-all'."
        }
    else:
        return {
            "level": "Critical Risk",
            "message": "No SPF record found. Domain is vulnerable to email spoofing.",
            "recommendation": "Create a valid SPF TXT record immediately."
        }


def analyze_dmarc(dmarc_records: list[str]) -> str:
    """Analyzes DMARC records and extracts policy action (p=reject, p=quarantine, p=none)."""
    if not dmarc_records:
        return "Missing"

    record = dmarc_records[0].lower()
    if "p=reject" in record:
        return "Strong"
    elif "p=quarantine" in record:
        return "Medium"
    elif "p=none" in record:
        return "Weak"
    else:
        return "Unknown"


def explain_dmarc_risk(dmarc_status: str) -> dict:
    """Returns human-readable explanation and recommendations for DMARC status."""
    if dmarc_status == "Strong":
        return {
            "level": "Low Risk",
            "message": "Spoofed emails are rejected by receiving servers (p=reject).",
            "recommendation": "DMARC policy is strictly enforced."
        }
    elif dmarc_status == "Medium":
        return {
            "level": "Medium Risk",
            "message": "Suspicious emails are moved to spam/quarantine (p=quarantine).",
            "recommendation": "Progressively move policy to 'p=reject'."
        }
    elif dmarc_status == "Weak":
        return {
            "level": "High Risk",
            "message": "DMARC is running in monitoring mode only (p=none); spoofed emails are not blocked.",
            "recommendation": "Advance policy to 'p=quarantine' or 'p=reject'."
        }
    else:
        return {
            "level": "Critical Risk",
            "message": "No DMARC record found. Domain can be impersonated by attackers.",
            "recommendation": "Deploy a DMARC policy record (_dmarc.<domain>) immediately."
        }


def get_spf_score(status: str) -> int:
    """Converts SPF status to a percentage score component."""
    return {
        "Strong": 100,
        "SoftFail": 60,
        "Weak": 30,
        "Missing": 0
    }.get(status, 0)


def get_dmarc_score(status: str) -> int:
    """Converts DMARC status to a percentage score component."""
    return {
        "Strong": 100,
        "Medium": 70,
        "Weak": 30,
        "Missing": 0,
        "Unknown": 20
    }.get(status, 0)


def classify_txt(txt_records: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Separates TXT records into SPF, DKIM-related, and other TXT records."""
    spf, dkim, other = [], [], []
    for record in txt_records:
        r = record.lower()
        if r.startswith("v=spf1"):
            spf.append(record)
        elif "dkim" in r:
            dkim.append(record)
        else:
            other.append(record)
    return spf, dkim, other


def calculate_email_security_score(
    mx: list[str],
    dmarc: list[str],
    spf_status: str,
    dkim: list[str]
) -> tuple[int, str, list[str]]:
    """
    Computes a composite security score (0-100), letter/verbal grade,
    and bulleted list of factors.
    """
    score = 0
    reasons = []

    if mx:
        score += 20
        reasons.append("MX records configured (mail delivery active)")

    if spf_status == "Strong":
        score += 30
        reasons.append("Strong SPF policy enforced (-all)")
    elif spf_status == "SoftFail":
        score += 20
        reasons.append("SPF SoftFail (~all) active")
    elif spf_status == "Weak":
        score += 10
        reasons.append("Weak SPF policy configured")

    if dmarc:
        status = analyze_dmarc(dmarc)
        if status == "Strong":
            score += 30
            reasons.append("DMARC reject policy enforced (p=reject)")
        elif status == "Medium":
            score += 20
            reasons.append("DMARC quarantine policy active (p=quarantine)")
        elif status == "Weak":
            score += 10
            reasons.append("DMARC present in monitoring mode (p=none)")

    if dkim:
        score += 20
        reasons.append("DKIM authentication records detected")

    score = min(score, 100)
    grade = "Strong" if score >= 80 else "Medium" if score >= 50 else "Weak"
    return score, grade, reasons
