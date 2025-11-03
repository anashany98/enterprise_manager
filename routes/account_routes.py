from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
import pandas as pd
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from forms import AccountForm, AccountImportForm
from models import Account, Device, User, db
from utils import log_action, role_required

bp = Blueprint("accounts", __name__, url_prefix="/accounts")


def _populate_form_choices(form: AccountForm) -> None:
    users = User.query.filter_by(active=True).order_by(User.name.asc()).all()
    devices = Device.query.order_by(Device.type.asc()).all()
    form.owner_id.choices = [(user.id, user.name) for user in users]
    if hasattr(form, "device_ids"):
        form.device_ids.choices = [
            (device.id, f"{device.serial_number} ({device.type})") for device in devices
        ]


def _password_is_reused(password: str, exclude_account_id: int | None = None) -> bool:
    query = Account.query.filter(Account.active.is_(True))
    if exclude_account_id:
        query = query.filter(Account.id != exclude_account_id)
    for account in query.all():
        try:
            if account.get_password() == password:
                return True
        except Exception:
            continue
    return False


@bp.route("/", methods=["GET"])
@login_required
def list_accounts():
    accounts = (
        Account.query.filter(Account.active.is_(True))
        .order_by(Account.updated_at.desc())
        .options(joinedload(Account.owner), joinedload(Account.devices))
        .all()
    )
    form = AccountForm()
    _populate_form_choices(form)
    import_form = AccountImportForm()
    return render_template("accounts.html", accounts=accounts, form=form, import_form=import_form)


@bp.route("/create", methods=["POST"])
@login_required
@role_required("admin", "technician")
def create_account():
    form = AccountForm()
    _populate_form_choices(form)
    current_app.logger.info("=== CREATE ACCOUNT DEBUG ===")
    current_app.logger.info(f"Request method: {request.method}")
    current_app.logger.info(f"Request form data: {dict(request.form)}")
    current_app.logger.info(f"Form data after creation: {form.data}")
    current_app.logger.info(f"Form errors before validation: {form.errors}")
    if form.validate_on_submit():
        password_plain = form.password.data
        if _password_is_reused(password_plain):
            flash("La contrasena ya esta siendo utilizada por otra cuenta.", "warning")
            return redirect(url_for("accounts.list_accounts"))

        account = Account(
            service=form.service.data,
            username=form.username.data,
            owner_id=form.owner_id.data,
            notes=form.notes.data,
            country=form.country.data,
            location=form.location.data,
            active=form.active.data,
        )
        account.set_password(password_plain)

        device_ids = [device_id for device_id in form.device_ids.data if device_id]
        if device_ids:
            account.devices = Device.query.filter(Device.id.in_(device_ids)).all()

        db.session.add(account)
        db.session.commit()
        flash("Cuenta creada correctamente.", "success")
        log_action("accounts.create", metadata={"account_id": account.id})
    else:
        current_app.logger.error(f"Form validation failed. Errors: {form.errors}")
        for field_name, errors in form.errors.items():
            field = getattr(form, field_name, None)
            label = field.label.text if field else field_name
            for error in errors:
                flash(f"{label}: {error}", "danger")
        flash("Error al crear la cuenta.", "danger")

    return redirect(url_for("accounts.list_accounts"))


def _parse_boolean(value, default=True):
    if value is None or pd.isna(value):
        return default
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"", "nan"}:
            return default
        return normalized in {"true", "1", "si", "yes", "activo", "activa"}
    return bool(value)


def _parse_optional_string(value: object) -> str:
    if value is None or pd.isna(value):
        return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


@bp.route("/import", methods=["POST"])
@login_required
@role_required("admin", "technician")
def import_accounts():
    form = AccountImportForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            label = field
            form_field = getattr(form, field, None)
            if form_field is not None and hasattr(form_field, "label"):
                label = form_field.label.text
            for error in errors:
                flash(f"{label}: {error}", "danger")
        flash("Error al importar las cuentas.", "danger")
        return redirect(url_for("accounts.list_accounts"))

    file_storage = form.file.data
    try:
        dataframe = pd.read_excel(file_storage)
    except Exception as exc:
        current_app.logger.exception("Failed reading accounts import", exc_info=exc)
        flash("No se pudo leer el archivo Excel. Verifique que el formato sea correcto.", "danger")
        return redirect(url_for("accounts.list_accounts"))

    if dataframe.empty:
        flash("El archivo no contiene registros para importar.", "warning")
        return redirect(url_for("accounts.list_accounts"))

    dataframe.columns = [str(column).strip().lower() for column in dataframe.columns]
    required_columns = {"service", "username", "password", "owner_email"}
    missing_columns = required_columns.difference(dataframe.columns)
    if missing_columns:
        flash(
            "Faltan columnas obligatorias en el Excel: " + ", ".join(sorted(missing_columns)),
            "danger",
        )
        return redirect(url_for("accounts.list_accounts"))

    processed = 0
    skipped = 0
    issues: list[str] = []

    for index, row in dataframe.iterrows():
        service = str(row.get("service", "")).strip()
        username = str(row.get("username", "")).strip()
        password_plain = str(row.get("password", "")).strip()
        owner_email_raw = row.get("owner_email", "")

        if not service or not username or not password_plain or pd.isna(owner_email_raw):
            skipped += 1
            issues.append(f"Fila {index + 2}: datos obligatorios incompletos.")
            continue

        owner_email = str(owner_email_raw).strip().lower()
        owner = User.query.filter(func.lower(User.email) == owner_email).first()
        if not owner:
            skipped += 1
            issues.append(f"Fila {index + 2}: usuario '{owner_email}' no encontrado.")
            continue

        existing_account = (
            Account.query.filter(
                func.lower(Account.service) == service.lower(),
                func.lower(Account.username) == username.lower(),
            )
            .filter(Account.active.is_(True))
            .first()
        )
        if existing_account:
            skipped += 1
            issues.append(f"Fila {index + 2}: la combinacion servicio/usuario ya existe.")
            continue

        if _password_is_reused(password_plain):
            skipped += 1
            issues.append(f"Fila {index + 2}: contrasena reutilizada en otra cuenta.")
            continue

        country = _parse_optional_string(row.get("country")) if "country" in dataframe.columns else ""
        location = _parse_optional_string(row.get("location")) if "location" in dataframe.columns else ""
        active = _parse_boolean(row.get("active")) if "active" in dataframe.columns else True

        device_serials_value = None
        if "device_serials" in dataframe.columns:
            device_serials_value = row.get("device_serials")
        elif "device_serial" in dataframe.columns:
            device_serials_value = row.get("device_serial")

        device_serials: list[str] = []
        if device_serials_value is not None and not pd.isna(device_serials_value):
            device_serials = [serial.strip() for serial in str(device_serials_value).split(",") if serial.strip()]

        devices_linked: list[Device] = []
        missing_devices: list[str] = []
        for serial in device_serials:
            device = Device.query.filter(func.lower(Device.serial_number) == serial.lower()).first()
            if device:
                devices_linked.append(device)
            else:
                missing_devices.append(serial)

        notes = _parse_optional_string(row.get("notes")) if "notes" in dataframe.columns else ""

        account = Account(
            service=service,
            username=username,
            owner=owner,
            notes=notes,
            country=country,
            location=location,
            active=active,
        )
        account.set_password(password_plain)
        if devices_linked:
            account.devices = devices_linked
        db.session.add(account)
        processed += 1

        if missing_devices:
            issues.append(
                f"Fila {index + 2}: dispositivos no encontrados ({', '.join(missing_devices)}). Asociacion omitida."
            )

    if processed:
        db.session.commit()
        flash(f"Se importaron {processed} cuentas correctamente.", "success")
        log_action(
            "accounts.import",
            metadata={"created": processed, "skipped": skipped, "issues": issues[:10]},
        )
    else:
        flash("No se crearon cuentas nuevas a partir del archivo proporcionado.", "warning")

    if skipped:
        flash(f"{skipped} filas se omitieron. Revise los detalles en los mensajes.", "info")
    for message in issues[:5]:
        flash(message, "warning")

    return redirect(url_for("accounts.list_accounts"))


@bp.route("/<int:account_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "technician")
def edit_account(account_id: int):
    account = Account.query.get_or_404(account_id)
    form = AccountForm(obj=account)
    _populate_form_choices(form)
    if request.method == "GET":
        form.device_ids.data = [device.id for device in account.devices]

    if request.method == "POST":
        if form.validate_on_submit():
            password_plain = form.password.data
            if _password_is_reused(password_plain, exclude_account_id=account.id):
                flash("La contrasena ya esta siendo utilizada por otra cuenta.", "warning")
                return redirect(url_for("accounts.edit_account", account_id=account.id))

            account.service = form.service.data
            account.username = form.username.data
            account.owner_id = form.owner_id.data
            account.notes = form.notes.data
            account.country = form.country.data
            account.location = form.location.data
            account.active = form.active.data

            device_ids = [device_id for device_id in form.device_ids.data if device_id]
            if device_ids:
                account.devices = Device.query.filter(Device.id.in_(device_ids)).all()
            else:
                account.devices = []

            account.set_password(password_plain)

            db.session.commit()
            flash("Cuenta actualizada.", "success")
            log_action("accounts.update", metadata={"account_id": account.id})
            return redirect(url_for("accounts.list_accounts"))

        flash("Error al actualizar la cuenta.", "danger")

    return render_template("account_edit.html", form=form, account=account)


@bp.route("/<int:account_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_account(account_id: int):
    account = Account.query.get_or_404(account_id)
    account.active = False
    db.session.commit()
    flash("Cuenta desactivada.", "info")
    log_action("accounts.deactivate", metadata={"account_id": account_id})
    return redirect(url_for("accounts.list_accounts"))


@bp.route("/<int:account_id>/reveal", methods=["POST"])
@login_required
def reveal_account_password(account_id: int):
    account = Account.query.get_or_404(account_id)
    if current_user.role not in {"admin", "technician"} and account.owner_id != current_user.id:
        return Response(status=403)

    password_plain = account.get_password()
    log_action("accounts.reveal_password", metadata={"account_id": account_id})
    return jsonify({"password": password_plain})
