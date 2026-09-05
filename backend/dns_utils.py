import dns.resolver
import socket
import ssl
import requests
from datetime import datetime


# ---------------- DNS RECORDS ----------------

import dns.resolver

# ---------------- DNS RESOLVER (IMPORTANT) ----------------
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google + Cloudflare
resolver.timeout = 5
resolver.lifetime = 5


# ---------------- MX RECORDS ----------------
def get_mx(domain):
    try:
        answers = resolver.resolve(domain, "MX")
        return [r.exchange.to_text().rstrip('.') for r in answers]
    except Exception as e:
        print("MX ERROR:", e)
        return []


# ---------------- TXT RECORDS ----------------
def get_txt(domain):
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
        print("TXT ERROR:", e)
    return records


# ---------------- DMARC RECORDS ----------------
def get_dmarc(domain):
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
        print("DMARC ERROR:", e)
        return []


# ---------------- SPF ANALYSIS ----------------

def analyze_spf(txt_records):
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            if "-all" in record:
                return "Strong"
            elif "~all" in record:
                return "SoftFail"
            else:
                return "Weak"
    return "Missing"

def explain_spf_risk(spf_status):
    if spf_status == "Strong":
        return {
            "level": "Low Risk",
            "message": "SPF strictly blocks unauthorized mail servers.",
            "recommendation": "No action required."
        }
    elif spf_status == "SoftFail":
        return {
            "level": "Medium Risk",
            "message": "Unauthorized senders are marked but not blocked.",
            "recommendation": "Change '~all' to '-all'."
        }
    elif spf_status == "Weak":
        return {
            "level": "High Risk",
            "message": "SPF exists but does not restrict senders.",
            "recommendation": "Define allowed servers and use '-all'."
        }
    else:
        return {
            "level": "Critical Risk",
            "message": "No SPF record found.",
            "recommendation": "Create an SPF record immediately."
        }

# ---------------- DMARC ANALYSIS ----------------

def analyze_dmarc(dmarc_records):
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

def explain_dmarc_risk(dmarc_status):
    if dmarc_status == "Strong":
        return {
            "level": "Low Risk",
            "message": "Spoofed emails are rejected.",
            "recommendation": "DMARC is correctly configured."
        }
    elif dmarc_status == "Medium":
        return {
            "level": "Medium Risk",
            "message": "Suspicious emails are quarantined.",
            "recommendation": "Change policy to 'reject'."
        }
    elif dmarc_status == "Weak":
        return {
            "level": "High Risk",
            "message": "DMARC is in monitoring mode only.",
            "recommendation": "Use 'quarantine' or 'reject'."
        }
    else:
        return {
            "level": "Critical Risk",
            "message": "No DMARC record found.",
            "recommendation": "Create a DMARC record immediately."
        }

# ---------------- RISK BAR SCORES ----------------

def get_spf_score(status):
    return {
        "Strong": 100,
        "SoftFail": 60,
        "Weak": 30,
        "Missing": 0
    }.get(status, 0)

def get_dmarc_score(status):
    return {
        "Strong": 100,
        "Medium": 70,
        "Weak": 30,
        "Missing": 0,
        "Unknown": 20
    }.get(status, 0)

# ---------------- TXT CLASSIFICATION ----------------

def classify_txt(txt_records):
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

# ---------------- EMAIL SECURITY SCORE ----------------

def calculate_email_security_score(mx, dmarc, spf_status, dkim):
    score = 0
    reasons = []

    if mx:
        score += 20
        reasons.append("MX records configured")

    if spf_status == "Strong":
        score += 30
        reasons.append("Strong SPF policy")
    elif spf_status == "SoftFail":
        score += 20
        reasons.append("SPF SoftFail (~all)")
    elif spf_status == "Weak":
        score += 10
        reasons.append("Weak SPF policy")

    if dmarc:
        status = analyze_dmarc(dmarc)
        if status == "Strong":
            score += 30
            reasons.append("DMARC reject policy")
        elif status == "Medium":
            score += 20
            reasons.append("DMARC quarantine policy")
        elif status == "Weak":
            score += 10
            reasons.append("DMARC monitoring only")

    if dkim:
        score += 20
        reasons.append("DKIM records present")

    score = min(score, 100)
    grade = "Strong" if score >= 80 else "Medium" if score >= 50 else "Weak"
    return score, grade, reasons

# ---------------- WEB INFO ----------------

def get_web_info(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            headers={"User-Agent": "DomainInfoScanner/1.0"}
        )
        headers = response.headers
        return {
            "Status Code": response.status_code,
            "Server": headers.get("Server", "Not disclosed"),
            "HSTS": headers.get("Strict-Transport-Security", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
        }
    except Exception as e:
        return {"Error": str(e)}

# ---------------- PORT SCAN ----------------

def scan_ports(domain, ports=None, timeout=1):
    if ports is None:
        ports = [21, 22, 25, 80, 443, 3306, 8080]

    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(f"{port} open")
            sock.close()
    except Exception as e:
        open_ports.append(str(e))
    return open_ports

# ---------------- DNSSEC ----------------

def check_dnssec(domain):
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if answers.rrset:
            return {
                "status": "Enabled",
                "risk": "Low Risk",
                "message": "DNSSEC is enabled and DNS responses are signed."
            }
        else:
            raise Exception()
    except:
        return {
            "status": "Not Enabled",
            "risk": "Medium Risk",
            "message": "DNSSEC is not enabled or not publicly accessible."
        }

# ---------------- HTTPS ----------------

def check_https(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            headers={"User-Agent": "DomainInfoScanner/1.0"}
        )
        return {
            "status": "HTTPS Enabled",
            "risk": "Low Risk",
            "message": f"HTTPS is enabled (Status {response.status_code})."
        }
    except requests.exceptions.SSLError:
        return {
            "status": "HTTPS Misconfigured",
            "risk": "High Risk",
            "message": "TLS certificate error detected."
        }
    except:
        return {
            "status": "HTTPS Not Available",
            "risk": "High Risk",
            "message": "Website does not support HTTPS."
        }
