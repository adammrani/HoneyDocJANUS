"""
src/tactical/watchdog.py
Filesystem watcher for the decoy drop directory.

Uses the `watchdog` library to record filesystem events (create / modify /
delete / move) as JSON lines in `data/fs_events.jsonl`. Useful to observe when
a decoy is touched on the shared drive.

CLI:
    python src/tactical/watchdog.py --path /srv/shared
"""

import argparse
import json
import os
from datetime import datetime, timezone

from src.core.config import get_settings
from src.core.logger import log

_settings = get_settings()
_EVENTS_FILE = os.path.join(_settings.DATA_DIR, "fs_events.jsonl")


def _record(event_type: str, src_path: str, is_directory: bool, dest_path: str = "") -> None:
    _settings.ensure_dirs()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "src_path": src_path,
        "dest_path": dest_path,
        "is_directory": is_directory,
    }
    with open(_EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    log.info("FS event: %s %s", event_type, src_path)


def watch(path: str) -> None:
    """Block and watch `path` recursively until interrupted."""
    from watchdog.events import FileSystemEventHandler  # lazy import
    from watchdog.observers import Observer

    class _Handler(FileSystemEventHandler):
        def on_created(self, event):
            _record("created", event.src_path, event.is_directory)

        def on_modified(self, event):
            _record("modified", event.src_path, event.is_directory)

        def on_deleted(self, event):
            _record("deleted", event.src_path, event.is_directory)

        def on_moved(self, event):
            _record("moved", event.src_path, event.is_directory, getattr(event, "dest_path", ""))

    os.makedirs(path, exist_ok=True)
    observer = Observer()
    observer.schedule(_Handler(), path, recursive=True)
    observer.start()
    log.info("Watching %s (Ctrl+C to stop) ...", path)
    try:
        while True:
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def main() -> None:
    parser = argparse.ArgumentParser(description="Watch a directory for filesystem events.")
    parser.add_argument("--path", default=_settings.DECOY_DROP_PATH, help="Directory to watch")
    args = parser.parse_args()
    watch(args.path)


if __name__ == "__main__":
    main()
