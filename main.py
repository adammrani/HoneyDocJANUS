"""Application entrypoint for the standalone JANUS service.

Starts:
  - the decoy infrastructure (fake SSH :2222 + fake HTTP :8080) in background,
  - the TTL rotation loop in a background thread,
  - the FastAPI server (uvicorn) on API_HOST:API_PORT.

Run:  python main.py
"""

import threading

import uvicorn

from src.core.config import get_settings
from src.core.database import init_db
from src.core.logger import log

_settings = get_settings()


def _start_background_services() -> None:
    """Launch decoy infra and rotation loop as daemon threads."""
    if _settings.DECOY_INFRA_ENABLED:
        try:
            from src.detection.decoy_infra import start_decoy_infra

            start_decoy_infra(
                http_port=_settings.DECOY_HTTP_PORT,
                ssh_port=_settings.DECOY_SSH_PORT,
                bind_host=_settings.DECOY_BIND_HOST,
            )
        except Exception as exc:  # noqa: BLE001 — never block API startup
            log.warning("Could not start decoy infrastructure: %s", exc)
    else:
        log.info("Decoy infrastructure is disabled.")

    try:
        from src.lifecycle.rotation_manager import run_loop

        threading.Thread(
            target=run_loop,
            kwargs={"interval_minutes": _settings.ROTATION_INTERVAL_MINUTES},
            name="janus-rotation-manager",
            daemon=True,
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
