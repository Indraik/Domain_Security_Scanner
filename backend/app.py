import os
from io import BytesIO
from flask import Flask, make_response, render_template, request
from xhtml2pdf import pisa

from dns_utils import (
    get_mx, get_txt, get_dmarc,
    analyze_spf, analyze_dmarc,
    explain_spf_risk, explain_dmarc_risk,
    classify_txt, calculate_email_security_score,
    get_web_info, scan_ports,
    check_dnssec, check_https,
    get_spf_score, get_dmarc_score
)

# Robust template & static paths for backend/frontend separation
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "..", "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "..", "frontend", "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)


@app.route("/", methods=["GET", "POST"])
def index():
    results = None

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()

        if domain:
            mx = get_mx(domain)
            txt = get_txt(domain)
            spf_records, dkim, other = classify_txt(txt)
            spf_status = analyze_spf(txt)

            dmarc = get_dmarc(domain)
            dmarc_status = analyze_dmarc(dmarc)

            score, grade, reasons = calculate_email_security_score(
                mx, dmarc, spf_status, dkim
            )

            results = {
                "domain": domain,
                "mx": mx,
                "dmarc": dmarc,
                "spf_status": spf_status,
                "dmarc_status": dmarc_status,
                "spf_explain": explain_spf_risk(spf_status),
                "dmarc_explain": explain_dmarc_risk(dmarc_status),
                "spf": spf_records,
                "dkim": dkim,
                "other": other,
                "score": score,
                "grade": grade,
                "reasons": reasons,
                "dnssec": check_dnssec(domain),
                "https": check_https(domain),
                "web_info": get_web_info(domain),
                "ports": scan_ports(domain),
                "spf_score": get_spf_score(spf_status),
                "dmarc_score": get_dmarc_score(dmarc_status)
            }

    return render_template("index.html", results=results)


@app.route("/report/pdf", methods=["POST"])
def generate_pdf():
    data = request.get_json()
    if not data:
        return make_response("Invalid request data", 400)

    # ---------- EXECUTIVE SUMMARY ----------
    summary = (
        f"The domain {data.get('domain', '')} was analyzed for email, DNS, and web security. "
        f"The overall verdict is {data.get('grade', 'N/A')} with a security score of {data.get('score', 0)}/100."
    )

    # ---------- RISK TEXT ----------
    spf_risk = "Low" if data.get("spf_score", 0) >= 30 else "Medium"
    dmarc_risk = "Low" if data.get("dmarc_score", 0) >= 30 else "High"
    dkim_risk = "Medium" if data.get("dkim") else "High"

    # ---------- RECOMMENDATIONS ----------
    recommendations = []

    if not data.get("dmarc"):
        recommendations.append("Implement DMARC to prevent email spoofing.")
    if not data.get("dkim"):
        recommendations.append("Configure DKIM for outgoing email authentication.")
    if not data.get("dnssec"):
        recommendations.append("Enable DNSSEC to protect DNS integrity.")
    if not recommendations:
        recommendations.append("No critical security issues detected. Maintain current configuration.")

    # ---------- RENDER PDF TEMPLATE ----------
    html = render_template(
        "report_pdf.html",
        domain=data.get("domain", ""),
        score=data.get("score", 0),
        verdict=data.get("grade", ""),
        scan_date=data.get("scan_date", "N/A"),
        summary=summary,

        spf_status=data.get("spf_status", ""),
        dmarc_status=data.get("dmarc_status", ""),
        dkim_status="Configured" if data.get("dkim") else "Not Configured",

        spf_risk=spf_risk,
        dmarc_risk=dmarc_risk,
        dkim_risk=dkim_risk,

        mx=data.get("mx", []),
        spf=data.get("spf", []),
        dmarc=data.get("dmarc", []),

        dnssec_status="Enabled" if data.get("dnssec") else "Not Enabled",
        https_status="Enabled" if data.get("https") else "Not Enabled",

        open_ports=data.get("ports", []),
        headers=data.get("web_info", {}),

        recommendations=recommendations
    )

    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)

    response = make_response(pdf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        "attachment; filename=domain_security_report.pdf"
    )
    return response


if __name__ == "__main__":
    app.run(debug=True)
