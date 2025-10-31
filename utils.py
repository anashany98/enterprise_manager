import datetime as dt
import functools
import json
from typing import Any, Callable, Dict, Optional

from flask import abort, current_app, flash, has_request_context, request
from flask_login import current_user

from .models import Log, db


def get_client_ip() -> str:
    """Return the best-effort client IP address."""
    if not has_request_context():
        return "system"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def role_required(*roles: str) -> Callable:
    """Decorator to enforce role-based access control."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            allowed = {role.lower() for role in roles}
            if current_user.role.lower() not in allowed:
                flash("No tiene permisos para acceder a esta seccion.", "danger")
                abort(403)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def log_action(action: str, *, metadata: Optional[Dict[str, Any]] = None) -> None:
    """Persist an audit log entry."""
    if current_app.config.get("TESTING"):
        return

    user_id = None
    if has_request_context() and current_user.is_authenticated:
        user_id = current_user.id

    meta_payload: Optional[Dict[str, Any]] = metadata or None
    if meta_payload:
        # Ensure metadata is JSON serializable
        try:
            json.dumps(meta_payload)
        except TypeError:
            meta_payload = {"detail": str(meta_payload)}

    entry = Log(
        user_id=user_id,
        action=action,
        ip_address=get_client_ip(),
        occurred_at=dt.datetime.utcnow(),
        metadata=meta_payload,
    )
    db.session.add(entry)
    db.session.commit()
