import io
import json
import os
import threading
import time
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import pandas as pd

# Apply stubs for third‑party dependencies when unavailable. This must be
# performed before importing modules such as ``flask`` or ``sqlalchemy``.
try:
    # When running as a package (``python -m enterprise_manager.app``), the
    # relative import will succeed.
    from .stubs import apply_stubs as _apply_stubs  # type: ignore
except ImportError:
    # Fallback when executing this file directly (e.g. ``python app.py``).
    # In this mode ``__package__`` is ``None`` and relative imports fail.
    import os as _os, sys as _sys, importlib as _importlib
    # Append the directory containing this file to sys.path so that
    # ``stubs`` can be imported as a top‑level module.
    _current_dir = _os.path.dirname(_os.path.abspath(__file__))
    if _current_dir not in _sys.path:
        _sys.path.insert(0, _current_dir)
    from stubs import apply_stubs as _apply_stubs  # type: ignore

_apply_stubs()

from flask import (  # type: ignore
    Flask,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required  # type: ignore
from flask_wtf import CSRFProtect  # type: ignore

csrf = CSRFProtect()
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer  # type: ignore
from reportlab.lib import colors  # type: ignore
from reportlab.lib.pagesizes import letter  # type: ignore
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle  # type: ignore
from werkzeug.middleware.proxy_fix import ProxyFix  # type: ignore

from sqlalchemy.orm import joinedload  # type: ignore

from config import Config, get_config
from crypto_utils import decrypt_blob, encrypt_blob
from models import Account, Device, Log, User, create_default_admin, db, login_manager
from routes import account_routes, auth_routes, device_routes, user_routes
from utils import log_action


def create_app(config_object: type[Config] | None = None) -> Flask:
    app = Flask(__name__)
    config_cls = config_object or get_config()
    app.config.from_object(config_cls)

    Path(app.config["BACKUP_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["REPORT_EXPORT_DIR"]).mkdir(parents=True, exist_ok=True)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Debe iniciar sesion para acceder a esta pagina."
    login_manager.login_message_category = "warning"

    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(user_routes.bp)
    app.register_blueprint(device_routes.bp)
    app.register_blueprint(account_routes.bp)

    _register_template_utils(app)
    _register_routes(app)
    _register_api(app)
    _register_cli(app)

    with app.app_context():
        db.create_all()
        create_default_admin()
        _start_backup_scheduler(app)

    return app


def _register_template_utils(app: Flask) -> None:
    @app.context_processor
    def inject_globals():
        return {
            "now": datetime.utcnow,
        }

    def format_datetime(value: datetime | None) -> str:
        if not value:
            return ""
        return value.strftime("%d/%m/%Y %H:%M")

    app.jinja_env.filters["datetime"] = format_datetime


def _register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("main.dashboard"))
        return redirect(url_for("auth.login"))

    main_bp = _create_main_blueprint()
    app.register_blueprint(main_bp)


def _create_main_blueprint():
    from flask import Blueprint

    bp = Blueprint("main", __name__)

    @bp.route("/dashboard")
    @login_required
    def dashboard():
        total_users = User.query.count()
        total_devices = Device.query.count()
        total_accounts = Account.query.count()

        devices_by_country = (
            db.session.query(Device.country, db.func.count(Device.id))
            .group_by(Device.country)
            .all()
        )
        devices_by_status = (
            db.session.query(Device.status, db.func.count(Device.id))
            .group_by(Device.status)
            .all()
        )
        accounts_by_user = (
            db.session.query(User.name, db.func.count(Account.id))
            .join(Account, Account.owner_id == User.id)
            .group_by(User.name)
            .all()
        )

        chart_data = {
            "devicesByCountry": _to_chart_dataset(devices_by_country),
            "devicesByStatus": _to_chart_dataset(devices_by_status),
            "accountsByUser": _to_chart_dataset(accounts_by_user),
        }

        recent_logs = Log.query.order_by(Log.occurred_at.desc()).limit(10).all()

        return render_template(
            "dashboard.html",
            total_users=total_users,
            total_devices=total_devices,
            total_accounts=total_accounts,
            chart_data=chart_data,
            recent_logs=recent_logs,
        )

    @bp.route("/logs")
    @login_required
    def view_logs():
        if current_user.role != "admin":
            abort(403)
        logs = Log.query.order_by(Log.occurred_at.desc()).limit(200).all()
        return render_template("logs.html", logs=logs)

    return bp


def _to_chart_dataset(pairs: Iterable[Tuple[str | None, int]]) -> Dict[str, Any]:
    labels, values = [], []
    for label, value in pairs:
        labels.append(label or "Desconocido")
        values.append(value)
    return {"labels": labels, "values": values}


def _register_api(app: Flask) -> None:
    api_bp = _create_api_blueprint(app)
    app.register_blueprint(api_bp)


def _create_api_blueprint(app: Flask):
    from flask import Blueprint

    bp = Blueprint("api", __name__, url_prefix="/api")
    csrf.exempt(bp)
    serializer = URLSafeTimedSerializer(app.config["JWT_SECRET_KEY"])

    def require_token(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                abort(401)
            token = auth_header.split(" ", 1)[1]
            try:
                payload = serializer.loads(token, max_age=int(app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()))
            except SignatureExpired:
                abort(401)
            except BadSignature:
                abort(401)
            request.api_user = payload  # type: ignore[attr-defined]
            return func(*args, **kwargs)

        return wrapper

    @bp.route("/token", methods=["POST"])
    def issue_token():
        data = request.get_json() or {}
        email = data.get("email", "").lower()
        password = data.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            abort(401)
        payload = {"user_id": user.id, "role": user.role}
        token = serializer.dumps(payload)
        log_action("api.token_issued", metadata={"user_id": user.id})
        return jsonify({"access_token": token, "expires_in": int(app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds())})

    @bp.route("/stats", methods=["GET"])
    @require_token
    def api_stats():
        return jsonify(
            {
                "users": User.query.count(),
                "devices": Device.query.count(),
                "accounts": Account.query.count(),
            }
        )

    @bp.route("/accounts", methods=["GET"])
    @require_token
    def api_accounts():
        accounts = [
            {
                "id": account.id,
                "service": account.service,
                "username": account.username,
                "owner": account.owner.name if account.owner else None,
                "device": account.device.serial_number if account.device else None,
                "notes": account.notes,
                "last_modified": account.last_modified.isoformat() if account.last_modified else None,
            }
            for account in Account.query.options(joinedload(Account.owner), joinedload(Account.device)).all()
        ]
        return jsonify({"accounts": accounts})

    return bp


def _register_cli(app: Flask) -> None:
    @app.cli.command("backup-db")
    def backup_db():
        """Create an encrypted backup immediately."""
        perform_backup()
        print("Backup creado correctamente.")


def _start_backup_scheduler(app: Flask) -> None:
    if app.config.get("_backup_thread_started"):
        return

    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    interval_hours = app.config.get("DATABASE_BACKUP_INTERVAL_HOURS", 24)

    def run():
        # Delay before first backup to avoid duplicate on startup
        time.sleep(5)
        while True:
            try:
                with app.app_context():
                    perform_backup()
            except Exception as exc:  # pragma: no cover
                app.logger.exception("Error during scheduled backup: %s", exc)
            time.sleep(interval_hours * 3600)

    thread = threading.Thread(target=run, daemon=True, name="backup-scheduler")
    thread.start()
    app.config["_backup_thread_started"] = True


def perform_backup() -> Path:
    """Create an encrypted backup of the database and return the path."""
    db_uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_uri.startswith("sqlite:///"):
        current_app.logger.info("Backup automatico omitido (solo soportado para SQLite por ahora).")
        return Path()

    db_path = Path(db_uri.replace("sqlite:///", ""))
    if not db_path.exists():
        current_app.logger.warning("El archivo de base de datos no existe: %s", db_path)
        return Path()

    backup_dir = Path(current_app.config["BACKUP_DIR"])
    backup_dir.mkdir(parents=True, exist_ok=True)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(db_path, arcname=db_path.name)
    encrypted_payload = encrypt_blob(buffer.getvalue())

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"empresa_{timestamp}.zip.enc"
    with open(backup_file, "wb") as fh:
        fh.write(encrypted_payload)

    current_app.logger.info("Backup creado en %s", backup_file)
    log_action("backup.created", metadata={"path": str(backup_file)})
    return backup_file


def restore_backup(encrypted_path: Path) -> None:
    """Restore a backup from an encrypted payload."""
    db_uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_uri.startswith("sqlite:///"):
        raise RuntimeError("La restauracion automatica solo esta disponible para SQLite.")

    db_path = Path(db_uri.replace("sqlite:///", ""))
    with open(encrypted_path, "rb") as fh:
        payload = fh.read()
    decrypted = decrypt_blob(payload)
    with zipfile.ZipFile(io.BytesIO(decrypted)) as archive:
        archive.extractall(db_path.parent)
    log_action("backup.restored", metadata={"path": str(encrypted_path)})


@login_required
def export_table(table: str, fmt: str):
    """Shared export logic used by multiple routes."""
    fmt = fmt.lower()
    if fmt not in {"csv", "xlsx", "pdf"}:
        abort(400, "Formato no soportado.")

    df = _table_to_dataframe(table)
    if df.empty:
        abort(404, "No hay datos para exportar.")

    filename = f"{table}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{fmt}"

    if fmt == "csv":
        buffer = io.StringIO()
        df.to_csv(buffer, index=False)
        buffer.seek(0)
        log_action("export.csv", metadata={"table": table})
        return send_file(
            io.BytesIO(buffer.getvalue().encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name=filename,
        )

    if fmt == "xlsx":
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        buffer.seek(0)
        log_action("export.xlsx", metadata={"table": table})
        return send_file(
            buffer,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=filename,
        )

    # PDF export
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    table_data = [list(df.columns)] + df.values.tolist()
    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ]
    )
    pdf_table = Table(table_data)
    pdf_table.setStyle(table_style)
    doc.build([pdf_table])
    buffer.seek(0)
    log_action("export.pdf", metadata={"table": table})
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


def _table_to_dataframe(table: str) -> pd.DataFrame:
    table = table.lower()
    if table == "users":
        data = [user.to_dict() for user in User.query.all()]
        return pd.DataFrame(data)
    if table == "devices":
        data = [device.to_dict() for device in Device.query.all()]
        return pd.DataFrame(data)
    if table == "accounts":
        data = [
            {
                **account.to_dict(),
                "owner": account.owner.name if account.owner else None,
                "device": account.device.serial_number if account.device else None,
            }
            for account in Account.query.options(joinedload(Account.owner), joinedload(Account.device)).all()
        ]
        return pd.DataFrame(data)
    if table == "logs":
        data = [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "ip_address": log.ip_address,
                "metadata": json.dumps(log.metadata) if log.metadata else None,
                "occurred_at": log.occurred_at,
            }
            for log in Log.query.all()
        ]
        return pd.DataFrame(data)
    abort(404, "Tabla no soportada.")


app = create_app()


@app.route("/export/<string:table>/<string:fmt>")
@login_required
def export_route(table: str, fmt: str):
    return export_table(table, fmt)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
