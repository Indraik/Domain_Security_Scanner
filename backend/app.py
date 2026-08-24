from flask import Flask, make_response, render_template, request

from dns_utils import (
    get_mx, get_txt, get_dmarc, get_dkim,
    analyze_spf, analyze_dmarc,
    explain_spf_risk, explain_dmarc_risk,
    classify_txt, calculate_email_security_score,
    get_web_info, scan_ports,
    check_dnssec, check_https,
    get_spf_score, get_dmarc_score
)


app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None

    if request.method == "POST":
        domain = request.form.get("domain").strip()

        mx = get_mx(domain)

        txt = get_txt(domain)

        spf_records, _, other = classify_txt(txt)
        spf_status = analyze_spf(txt)

        dkim = get_dkim(domain)

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

from xhtml2pdf import pisa
from io import BytesIO

@app.route("/report/pdf", methods=["POST"])
def generate_pdf():
    data = request.get_json()

    html = render_template("report.html", results=data)

    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)

    response = make_response(pdf.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=domain_security_report.pdf"
    return response


if __name__ == "__main__":
    app.run(debug=True)
