from flask import Blueprint, render_template, request
from app.services.scanner_orchestrator import scan_domain
from app.utils.validators import validate_domain

web_bp = Blueprint("web", __name__)


@web_bp.route("/", methods=["GET", "POST"])
def index():
    """Serves the main interface, supporting both initial load and traditional POST fallback."""
    results = None
    error = None

    if request.method == "POST":
        raw_domain = request.form.get("domain", "").strip()
        is_valid, domain_or_err = validate_domain(raw_domain)
        if is_valid:
            results = scan_domain(domain_or_err)
        else:
            error = domain_or_err

    return render_template("index.html", results=results, error=error)
