"""Logging for every entry point: stdout plus a rotating logs/app.log.

Library modules only call ``logging.getLogger("<package>.<module>")``. Entry
points (the CLIs and the Streamlit app) call :func:`configure_logging` once.
It is idempotent, so Streamlit reruns and repeated calls never stack duplicate
handlers.

Log messages use ``key=value`` pairs so they can be grepped and parsed. They
never contain packet payloads, IP addresses or the API key: file names are
logged as base names and sessions by their session_id.
"""

import logging
import logging.handlers
import os
import sys

import config

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# Third-party loggers that are chatty at INFO and irrelevant to this app.
QUIET_LOGGERS = ("scapy", "urllib3", "fontTools", "PIL", "matplotlib")

_CONFIGURED_ATTR = "_ipsec_logging_configured"


def configure_logging(level=None):
    """Attach the stdout and rotating-file handlers to the root logger once.

    `level` overrides config.LOG_LEVEL. If the log directory cannot be created
    (read-only checkout, for example) the app keeps running with stdout only
    and logs a warning saying so. Returns the root logger.
    """
    root = logging.getLogger()
    if getattr(root, _CONFIGURED_ATTR, False):
        return root

    formatter = logging.Formatter(LOG_FORMAT)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    file_error = None
    try:
        os.makedirs(config.LOG_DIR, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError as exc:
        file_error = exc
    else:
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    root.setLevel(level or config.LOG_LEVEL)
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    setattr(root, _CONFIGURED_ATTR, True)

    log = logging.getLogger("ipsec.logging")
    if file_error is not None:
        log.warning(
            "file logging disabled path=%s reason=%s",
            config.LOG_FILE,
            type(file_error).__name__,
        )
    for message in config.CONFIG_WARNINGS:
        log.warning("config override ignored: %s", message)
    return root
