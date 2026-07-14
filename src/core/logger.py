"""
src/core/logger.py
Single shared logger for the whole project.

Import `log` anywhere:  `from src.core.logger import log`
It writes both to the console and to `data/honeydocs.log`.
"""

import logging
import os

from src.core.config import get_settings

_settings = get_settings()
_settings.ensure_dirs()

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("honeydocs")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if this module is imported multiple times.
    if logger.handlers:
        return logger

    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        os.makedirs(os.path.dirname(_settings.LOG_FILE), exist_ok=True)
        file_handler = logging.FileHandler(_settings.LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # If the log file cannot be created, keep console logging only.
        logger.warning("Could not open log file; console logging only.")

    logger.propagate = False
    return logger


log = _build_logger()
