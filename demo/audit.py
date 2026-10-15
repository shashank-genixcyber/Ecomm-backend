"""One append writer for all demo threads; never serialize arbitrary log messages."""
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from threading import RLock
from uuid import uuid4

context = ContextVar("demo_audit_context", default={})
_lock = RLock()


class AuditUnavailable(Exception):
    pass


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def environment_name():
    value = os.getenv("ECOMM_DEMO_ENVIRONMENT", "development").strip().lower()
    if value not in {"production", "testing", "development", "staging"}:
        raise ValueError("ECOMM_DEMO_ENVIRONMENT must be production, testing, development or staging.")
    return value


def emit(event, *, path=None, **fields):
    if path is None:
        from django.conf import settings
        path = settings.DEMO_LOG_PATH
    record = {"schema_version": 1, "event_id": str(uuid4()), "timestamp": timestamp(),
              "level": "INFO", **context.get(), "event_type": event, **fields}
    record["environment"] = environment_name()
    line = (json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()
    try:
        with _lock:
            descriptor = os.open(Path(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "ab") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
    except (OSError, ValueError) as error:
        raise AuditUnavailable("The demo audit file is unavailable.") from None
    return record


class SafeLogHandler(logging.Handler):
    """Retain severity/source and safe stack locations, never interpolated messages.

    Django's server messages can contain OAuth callback codes; third-party
    exceptions can contain headers or bodies. Structured producers record the
    useful request/credential metadata separately.
    """
    def emit(self, record):
        locations = []
        if record.exc_info and record.exc_info[2]:
            traceback = record.exc_info[2]
            while traceback:
                locations.append({"file": Path(traceback.tb_frame.f_code.co_filename).name,
                                  "line": traceback.tb_lineno, "function": traceback.tb_frame.f_code.co_name})
                traceback = traceback.tb_next
        try:
            emit("application.log", level=record.levelname, logger=record.name,
                 error_type=record.exc_info[0].__name__ if record.exc_info else None, stack=locations)
        except AuditUnavailable:
            # Credential operations use emit() directly and fail closed. Avoid
            # recursive logging or leaking the failed record to stderr here.
            pass
