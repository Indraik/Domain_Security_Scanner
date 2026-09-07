import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from app.config import Config
from app.services.dns_service import get_mx, get_txt, get_dmarc, check_dnssec
from app.services.email_security import (
    classify_txt,
    analyze_spf,
    analyze_dmarc,
    explain_spf_risk,
    explain_dmarc_risk,
    get_spf_score,
    get_dmarc_score,
    calculate_email_security_score,
)
from app.services.web_security import get_web_info, check_https
from app.services.port_scanner import scan_ports

logger = logging.getLogger(__name__)


def scan_domain(domain: str) -> dict:
    """
    Orchestrates high-speed concurrent analysis across all security vectors.
    Executes DNS, Web, and Port audits in parallel via ThreadPoolExecutor.
    """
    logger.info(f"Initiating parallel security audit for domain: {domain}")

    with ThreadPoolExecutor(max_workers=Config.MAX_SCAN_WORKERS) as executor:
        # Submit tasks in parallel
        f_mx = executor.submit(get_mx, domain)
        f_txt = executor.submit(get_txt, domain)
        f_dmarc = executor.submit(get_dmarc, domain)
        f_dnssec = executor.submit(check_dnssec, domain)
        f_https = executor.submit(check_https, domain)
        f_web_info = executor.submit(get_web_info, domain)
        f_ports = executor.submit(scan_ports, domain)

        # Await results
        mx = f_mx.result()
        txt = f_txt.result()
        dmarc = f_dmarc.result()
        dnssec = f_dnssec.result()
        https = f_https.result()
        web_info = f_web_info.result()
        ports = f_ports.result()

    # Email security analysis & policy evaluations
    spf_records, dkim, other = classify_txt(txt)
    spf_status = analyze_spf(txt)
    dmarc_status = analyze_dmarc(dmarc)

    score, grade, reasons = calculate_email_security_score(
        mx=mx,
        dmarc=dmarc,
        spf_status=spf_status,
        dkim=dkim
    )

    spf_score = get_spf_score(spf_status)
    dmarc_score = get_dmarc_score(dmarc_status)

    return {
        "domain": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
        "dnssec": dnssec,
        "https": https,
        "web_info": web_info,
        "ports": ports,
        "spf_score": spf_score,
        "dmarc_score": dmarc_score
    }
