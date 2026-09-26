"""Lance FastAPI et Streamlit avec une seule commande : python run.py."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from janus.config import Settings


ROOT = Path(__file__).resolve().parent


def wait_for_api(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
        time.sleep(0.25)
    raise RuntimeError(f"L'API JANUS n'a pas démarré : {last_error}")


def terminate(process: subprocess.Popen[bytes] | None) -> None:
    if not process or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()


def main() -> None:
    settings = Settings.from_project(ROOT)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT)
    environment["JANUS_API_URL"] = settings.api_url

    api: subprocess.Popen[bytes] | None = None
    dashboard: subprocess.Popen[bytes] | None = None
    try:
        api = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "janus.api:app",
                "--host",
                settings.api_host,
                "--port",
                str(settings.api_port),
            ],
            cwd=ROOT,
            env=environment,
        )
        wait_for_api(settings.api_url)
        dashboard = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "dashboard.py",
                "--server.address",
                settings.streamlit_host,
                "--server.port",
                str(settings.streamlit_port),
                "--server.headless",
                "true",
                "--server.fileWatcherType",
                "none",
                "--browser.gatherUsageStats",
                "false",
            ],
            cwd=ROOT,
            env=environment,
        )
        display_host = (
            "127.0.0.1" if settings.streamlit_host == "0.0.0.0" else settings.streamlit_host
        )
        print(f"JANUS prêt : http://{display_host}:{settings.streamlit_port}")
        print(f"API de collecte : {settings.public_base_url}")
        while True:
            if api.poll() is not None:
                raise RuntimeError(f"L'API JANUS s'est arrêtée (code {api.returncode}).")
            if dashboard.poll() is not None:
                raise RuntimeError(
                    f"Le dashboard Streamlit s'est arrêté (code {dashboard.returncode})."
                )
            time.sleep(1)
    except KeyboardInterrupt:
        print("Arrêt de JANUS…")
    finally:
        terminate(dashboard)
        terminate(api)


if __name__ == "__main__":
    main()

