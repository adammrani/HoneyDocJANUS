"""
src/detection/decoy_infra.py
Low-interaction decoy infrastructure (CI3 trap endpoints).

The CI3 layer plants fake credentials in the decoy document that point here.
Anyone who tries to *use* those credentials hits one of two passive listeners
that only log the attempt and notify the alert server:

  - Fake SSH on port 2222: sends a realistic SSH banner, reads the client
    banner, logs the source IP, then closes. It never authenticates anything.
  - Fake HTTP on port 8080: accepts POST /api/login, logs the submitted body
    (the stolen decoy credentials), and returns a generic error.

Both are honeypots: they observe and report, they do not attack or grant access.
"""

import json
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()

_SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"


def _notify_alert(trigger: str, src_ip: str, extra: dict) -> None:
    """Best-effort POST to our own /alert endpoint. Never raises."""
    payload = {
        "token_id": extra.get("token_id", trigger),
        "src_ip": src_ip,
        "user_agent": extra.get("user_agent", trigger),
        "trigger": trigger,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    try:
        requests.post(
            f"{_settings.CALLBACK_BASE_URL}/alert",
            json=payload,
            timeout=4,
        )
    except requests.RequestException as exc:
        log.warning("decoy_infra: could not notify /alert (%s)", exc)


# ── Fake SSH ─────────────────────────────────────────────

def _handle_ssh_client(client: socket.socket, addr) -> None:
    src_ip = addr[0]
    try:
        client.settimeout(5)
        client.sendall(_SSH_BANNER)
        try:
            client_banner = client.recv(256).decode("utf-8", "replace").strip()
        except socket.timeout:
            client_banner = ""
        log.warning("CI3 SSH probe from %s (client=%r)", src_ip, client_banner)
        _notify_alert(
            "CI3_SSH_PROBE",
            src_ip,
            {"user_agent": client_banner or "ssh-client"},
        )
    except OSError as exc:
        log.warning("decoy SSH error from %s: %s", src_ip, exc)
    finally:
        try:
            client.close()
        except OSError:
            pass


def _run_ssh_server(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(5)
        log.info("Decoy SSH listening on :%d", port)
    except OSError as exc:
        log.error("Could not bind decoy SSH on :%d (%s)", port, exc)
        return

    while True:
        try:
            client, addr = srv.accept()
        except OSError:
            break
        threading.Thread(
            target=_handle_ssh_client, args=(client, addr), daemon=True
        ).start()


# ── Fake HTTP ────────────────────────────────────────────

class _DecoyHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # silence default stderr logging
        pass

    def _capture(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        src_ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "")
        log.warning("CI3 API probe from %s on %s body=%r", src_ip, self.path, body)
        _notify_alert(
            "CI3_API_PROBE",
            src_ip,
            {"user_agent": ua, "path": self.path, "captured_body": body},
        )

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        self._capture()
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "invalid_credentials"}).encode())

    def do_GET(self) -> None:  # noqa: N802
        self._capture()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok"}).encode())


def _run_http_server(port: int) -> None:
    try:
        httpd = HTTPServer(("0.0.0.0", port), _DecoyHTTPHandler)
        log.info("Decoy HTTP listening on :%d", port)
        httpd.serve_forever()
    except OSError as exc:
        log.error("Could not bind decoy HTTP on :%d (%s)", port, exc)


# ── Public entrypoint ────────────────────────────────────

def start_decoy_infra(http_port: int = 8080, ssh_port: int = 2222) -> None:
    """Launch both fake listeners in background daemon threads."""
    threading.Thread(target=_run_ssh_server, args=(ssh_port,), daemon=True).start()
    threading.Thread(target=_run_http_server, args=(http_port,), daemon=True).start()
    log.info("Decoy infrastructure started (SSH:%d, HTTP:%d)", ssh_port, http_port)


if __name__ == "__main__":
    import time

    start_decoy_infra()
    log.info("Decoy infra running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("Decoy infra stopped.")
