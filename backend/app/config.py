import os

class Config:
    """Application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "domain-scanner-super-secret-key")
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
    
    # DNS Settings
    DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
    DNS_TIMEOUT = 5.0
    DNS_LIFETIME = 5.0
    
    # Web & HTTP Settings
    HTTP_TIMEOUT = 5.0
    USER_AGENT = "DomainInfoScanner/2.0 (Security Auditor)"
    
    # Port Scanner Settings
    DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
    PORT_TIMEOUT = 0.8
    MAX_PORT_WORKERS = 10
    
    # Scanner Orchestrator Concurrency
    MAX_SCAN_WORKERS = 5
