import logging
import requests
from app.config import Config

logger = logging.getLogger(__name__)


def get_web_info(domain: str) -> dict:
    """Fetches HTTP response headers and audits web security headers."""
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=Config.HTTP_TIMEOUT,
            headers={"User-Agent": Config.USER_AGENT},
            allow_redirects=True
        )
        headers = response.headers
        return {
            "Status Code": response.status_code,
            "Server": headers.get("Server", "Not disclosed"),
            "HSTS": headers.get("Strict-Transport-Security", "Missing"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Content-Security-Policy": "Configured" if "Content-Security-Policy" in headers else "Missing",
            "Referrer-Policy": headers.get("Referrer-Policy", "Missing")
        }
    except requests.exceptions.SSLError:
        return {"Error": "SSL/TLS handshake failed while fetching headers"}
    except requests.exceptions.ConnectionError:
        # Try fallback to HTTP if HTTPS fails
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=Config.HTTP_TIMEOUT,
                headers={"User-Agent": Config.USER_AGENT}
            )
            return {
                "Status Code": response.status_code,
                "Server": response.headers.get("Server", "Not disclosed"),
                "HTTPS Warning": "Website only responded over unencrypted HTTP",
                "HSTS": "Missing",
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Missing"),
            }
        except Exception as e:
            return {"Error": f"Could not connect to web host: {str(e)}"}
    except Exception as e:
        logger.warning(f"Web info error for {domain}: {e}")
        return {"Error": str(e)}


def check_https(domain: str) -> dict:
    """Verifies HTTPS availability and TLS certificate validity."""
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=Config.HTTP_TIMEOUT,
            headers={"User-Agent": Config.USER_AGENT}
        )
        return {
            "status": "HTTPS Enabled",
            "risk": "Low Risk",
            "message": f"HTTPS is enabled and responding normally (HTTP {response.status_code})."
        }
    except requests.exceptions.SSLError:
        return {
            "status": "HTTPS Misconfigured",
            "risk": "High Risk",
            "message": "TLS certificate is invalid, untrusted, or expired."
        }
    except Exception:
        return {
            "status": "HTTPS Not Available",
            "risk": "High Risk",
            "message": "Domain does not support or actively respond to HTTPS connections."
        }
