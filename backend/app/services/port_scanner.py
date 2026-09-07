import socket
from concurrent.futures import ThreadPoolExecutor
from app.config import Config

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def check_single_port(ip: str, port: int, timeout: float) -> str | None:
    """Checks a single TCP port on the target IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            service = PORT_SERVICES.get(port, "TCP")
            return f"{port} open ({service})"
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(domain: str, ports: list[int] = None, timeout: float = None) -> list[str]:
    """
    High-speed concurrent port scanner using ThreadPoolExecutor.
    Scans multiple target ports in parallel, dramatically cutting latency.
    """
    if ports is None:
        ports = Config.DEFAULT_PORTS
    if timeout is None:
        timeout = Config.PORT_TIMEOUT

    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        with ThreadPoolExecutor(max_workers=Config.MAX_PORT_WORKERS) as executor:
            futures = [
                executor.submit(check_single_port, ip, port, timeout)
                for port in ports
            ]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)

    except socket.gaierror:
        open_ports.append(f"Host resolution failed for {domain}")
    except Exception as e:
        open_ports.append(f"Scan error: {str(e)}")

    if not open_ports:
        open_ports.append("No standard public ports open")

    return open_ports
