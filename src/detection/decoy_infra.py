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
import hashlib
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from src.core.database import get_token_by_id, init_db, insert_alert
from src.core.logger import log
from src.detection.canarytoken_handler import parse_callback

_SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"


def _notify_alert(trigger: str, src_ip: str, extra: dict) -> None:
    """Persist a honeypot observation without trusting a public callback."""

    token_id = str(extra.get("token_id") or trigger)
    token_row = get_token_by_id(token_id)
    honeydoc_id = token_row["honeydoc_id"] if token_row else None
    user_agent = str(extra.get("user_agent") or trigger)
    payload = {
        "token_id": token_id,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "trigger": trigger,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    try:
        enriched = parse_callback(payload)
        insert_alert(
            token_id=token_id,
            honeydoc_id=honeydoc_id,
            src_ip=src_ip,
            user_agent=user_agent,
            os_guess=enriched.get("os_guess"),
            os_evidence_source=enriched.get("os_evidence_source", "none"),
            os_confidence=enriched.get("os_confidence", "none"),
            os_scope=enriched.get("os_scope", "unknown"),
            browser_guess=enriched.get("browser_guess"),
            raw_payload=payload,
        )
    except Exception as exc:  # noqa: BLE001 - honeypot listener must survive
        log.warning("decoy_infra: could not persist alert (%s)", exc)


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


def _run_ssh_server(bind_host: str, port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_host, port))
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
        try:
            declared_length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            declared_length = 0
        length = min(max(declared_length, 0), 16 * 1024)
        self.connection.settimeout(5)
        try:
            body = self.rfile.read(length) if length else b""
        except (socket.timeout, OSError):
            body = b""
        src_ip = self.client_address[0]
        ua = self.headers.get("User-Agent", "")
        path = urlparse(self.path).path
        parts = [part for part in path.split("/") if part]
        token_id = (
            parts[2]
            if (
                len(parts) == 3
                and parts[:2] == ["api", "login"]
                and len(parts[2]) <= 256
            )
            else ""
        )
        log.warning(
            "CI3 API probe from %s on %s (bytes=%d token=%s)",
            src_ip,
            path,
            declared_length,
            token_id or "unattributed",
        )
        _notify_alert(
            "CI3_API_PROBE",
            src_ip,
            {
                "token_id": token_id or "CI3_API_PROBE",
                "user_agent": ua,
                "path": path,
                "body_size": declared_length,
                "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
                "body_truncated": declared_length > length,
            },
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


def _run_http_server(bind_host: str, port: int) -> None:
    try:
        httpd = ThreadingHTTPServer((bind_host, port), _DecoyHTTPHandler)
        log.info("Decoy HTTP listening on :%d", port)
        httpd.serve_forever()
    except OSError as exc:
        log.error("Could not bind decoy HTTP on :%d (%s)", port, exc)


# ── Public entrypoint ────────────────────────────────────

def start_decoy_infra(
    http_port: int = 8080,
    ssh_port: int = 2222,
    bind_host: str = "127.0.0.1",
) -> None:
    """Launch both fake listeners in background daemon threads."""
    init_db()
    threading.Thread(
        target=_run_ssh_server,
        args=(bind_host, ssh_port),
        name="janus-decoy-ssh",
        daemon=True,
    ).start()
    threading.Thread(
        target=_run_http_server,
        args=(bind_host, http_port),
        name="janus-decoy-http",
        daemon=True,
    ).start()
    log.info(
        "Decoy infrastructure started on %s (SSH:%d, HTTP:%d)",
        bind_host,
        ssh_port,
        http_port,
    )


if __name__ == "__main__":
    import time

    start_decoy_infra()
    log.info("Decoy infra running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("Decoy infra stopped.")
