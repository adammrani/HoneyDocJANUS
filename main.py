"""
src/main.py
Application entrypoint.

Starts:
  - the decoy infrastructure (fake SSH :2222 + fake HTTP :8080) in background,
  - the TTL rotation loop in a background thread,
  - the FastAPI server (uvicorn) on API_HOST:API_PORT.

Run:  python src/main.py
"""

import threading

import uvicorn

from src.core.config import get_settings
from src.core.database import init_db
from src.core.logger import log

_settings = get_settings()


def _start_background_services() -> None:
    """Launch decoy infra and rotation loop as daemon threads."""
    try:
        from src.detection.decoy_infra import start_decoy_infra

        start_decoy_infra(http_port=8080, ssh_port=2222)
    except Exception as exc:  # noqa: BLE001 — never block API startup
        log.warning("Could not start decoy infrastructure: %s", exc)

    try:
        from src.lifecycle.rotation_manager import run_loop

        threading.Thread(
            target=run_loop, kwargs={"interval_minutes": 30}, daemon=True
        ).start()
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not start rotation loop: %s", exc)


def main() -> None:
    _settings.ensure_dirs()
    init_db()
    _start_background_services()

    log.info("Starting API on %s:%d", _settings.API_HOST, _settings.API_PORT)
    uvicorn.run(
        "src.alerting.alert_server:app",
        host=_settings.API_HOST,
        port=_settings.API_PORT,
        reload=False,
    )


if __name__ == "__main__":
    main()
