from datetime import datetime
from io import BytesIO
from flask import render_template
from xhtml2pdf import pisa


def generate_executive_summary(domain: str, score: int, grade: str) -> str:
    """Generates an executive-level assessment overview."""
    return (
        f"The domain '{domain}' was evaluated for email authentication, DNS security, and external attack surface. "
        f"The composite security rating is {grade} with an overall score of {score}/100."
    )


def build_recommendations(data: dict) -> list[str]:
    """Builds prioritized remediation recommendations from scan telemetry."""
    recommendations = []

    spf_status = data.get("spf_status", "")
    if spf_status == "Missing":
        recommendations.append("Deploy a valid SPF TXT record with '-all' or '~all' mechanism.")
    elif spf_status in ("Weak", "SoftFail"):
        recommendations.append("Harden SPF record: upgrade mechanism from '~all' to hard-fail '-all'.")

    dmarc = data.get("dmarc")
    dmarc_status = data.get("dmarc_status", "")
    if not dmarc or dmarc_status == "Missing":
        recommendations.append("Implement DMARC policy (_dmarc.<domain>) to prevent spoofing and domain impersonation.")
    elif dmarc_status == "Weak":
        recommendations.append("Advance DMARC policy from 'p=none' (monitoring) to 'p=quarantine' or 'p=reject'.")

    if not data.get("dkim"):
        recommendations.append("Configure DKIM cryptographic signing on all outbound mail servers.")

    dnssec = data.get("dnssec")
    dnssec_enabled = False
    if isinstance(dnssec, dict):
        dnssec_enabled = dnssec.get("status") == "Enabled"
    elif isinstance(dnssec, bool):
        dnssec_enabled = dnssec
    if not dnssec_enabled:
        recommendations.append("Enable DNSSEC at your registrar/DNS provider to protect against DNS cache poisoning.")

    https = data.get("https")
    if isinstance(https, dict) and https.get("risk") == "High Risk":
        recommendations.append("Enforce valid HTTPS/TLS certificates and enable automatic HTTP-to-HTTPS redirection.")

    if not recommendations:
        recommendations.append("No critical security misconfigurations detected. Maintain existing security policies.")

    return recommendations


def generate_pdf_report(data: dict) -> bytes:
    """Renders the HTML PDF template and compiles it to PDF binary bytes."""
    domain = data.get("domain", "Unknown")
    score = data.get("score", 0)
    grade = data.get("grade", "N/A")
    scan_date = data.get("scan_date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = generate_executive_summary(domain, score, grade)

    spf_score = data.get("spf_score", 0)
    dmarc_score = data.get("dmarc_score", 0)
    spf_risk = "Low" if spf_score >= 80 else ("Medium" if spf_score >= 50 else "High")
    dmarc_risk = "Low" if dmarc_score >= 80 else ("Medium" if dmarc_score >= 50 else "High")
    dkim_risk = "Low" if data.get("dkim") else "Medium"

    dnssec = data.get("dnssec")
    if isinstance(dnssec, dict):
        dnssec_status = dnssec.get("status", "Not Enabled")
    else:
        dnssec_status = "Enabled" if dnssec else "Not Enabled"

    https = data.get("https")
    if isinstance(https, dict):
        https_status = https.get("status", "Not Enabled")
    else:
        https_status = "Enabled" if https else "Not Enabled"

    recommendations = build_recommendations(data)

    html = render_template(
        "report_pdf.html",
        domain=domain,
        score=score,
        verdict=grade,
        scan_date=scan_date,
        summary=summary,

        spf_status=data.get("spf_status", "Missing"),
        dmarc_status=data.get("dmarc_status", "Missing"),
        dkim_status="Configured" if data.get("dkim") else "Not Configured",

        spf_risk=spf_risk,
        dmarc_risk=dmarc_risk,
        dkim_risk=dkim_risk,

        mx=data.get("mx", []),
        spf=data.get("spf", []),
        dmarc=data.get("dmarc", []),

        dnssec_status=dnssec_status,
        https_status=https_status,

        open_ports=data.get("ports", []),
        headers=data.get("web_info", {}),

        recommendations=recommendations
    )

    pdf_buffer = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_buffer)
    if pisa_status.err:
        raise RuntimeError("PDF generation failed in pisa compiler")

    return pdf_buffer.getvalue()
