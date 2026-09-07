import logging
from flask import Blueprint, request, jsonify, make_response
from app.services.scanner_orchestrator import scan_domain
from app.services.report_service import generate_pdf_report
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)
api_bp = Blueprint("api", __name__)


@api_bp.route("/scan", methods=["POST"])
def scan_endpoint():
    """
    Asynchronous JSON scan endpoint.
    Accepts: { "domain": "example.com" }
    """
    payload = request.get_json(silent=True) or request.form
    raw_domain = payload.get("domain", "")

    is_valid, domain_or_err = validate_domain(raw_domain)
    if not is_valid:
        return jsonify({
            "success": False,
            "error": domain_or_err
        }), 400

    try:
        results = scan_domain(domain_or_err)
        return jsonify({
            "success": True,
            "data": results
        }), 200
    except Exception as e:
        logger.exception(f"Unexpected error during scan of '{domain_or_err}': {e}")
        return jsonify({
            "success": False,
            "error": f"Internal scan error: {str(e)}"
        }), 500


@api_bp.route("/report/pdf", methods=["POST"])
def pdf_endpoint():
    """
    Generates and streams a downloadable PDF report from scan payload data.
    """
    data = request.get_json(silent=True)
    if not data:
        return make_response("Invalid or missing report data", 400)

    try:
        pdf_bytes = generate_pdf_report(data)
        domain = data.get("domain", "security_report").replace(".", "_")
        filename = f"{domain}_security_report.pdf"

        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response
    except Exception as e:
        logger.exception(f"PDF generation error: {e}")
        return make_response(f"Failed to generate PDF: {str(e)}", 500)
