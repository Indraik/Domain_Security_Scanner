import os
import logging
from flask import Flask
from app.config import Config


def create_app(config_class=Config):
    """
    Application Factory for Domain Security Scanner.
    Initializes Flask, binds configuration, and registers blueprints.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )

    # Base directories
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_root = os.path.dirname(backend_dir)

    template_dir = os.path.join(project_root, "frontend", "templates")
    static_dir = os.path.join(project_root, "frontend", "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )
    app.config.from_object(config_class)

    # Register blueprints
    from app.routes.web import web_bp
    from app.routes.api import api_bp, pdf_endpoint

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    # Compatibility route for legacy /report/pdf
    app.add_url_rule("/report/pdf", "legacy_pdf", pdf_endpoint, methods=["POST"])

    return app
