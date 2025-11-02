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
from sqlalchemy.orm import joinedload

from forms import AccountForm
from models import Account, Device, User, db
from utils import log_action, role_required

bp = Blueprint("accounts", __name__, url_prefix="/accounts")


def _populate_form_choices(form: AccountForm) -> None:
    users = User.query.filter_by(active=True).order_by(User.name.asc()).all()
    devices = Device.query.order_by(Device.type.asc()).all()
    form.owner_id.choices = [(user.id, user.name) for user in users]
    form.device_id.choices = [(None, "Sin dispositivo")] + [(d.id, d.serial_number) for d in devices]


def _password_is_reused(password: str, exclude_account_id: int | None = None) -> bool:
    query = Account.query
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
        Account.query.order_by(Account.updated_at.desc())
        .options(joinedload(Account.owner), joinedload(Account.device))
        .all()
    )
    form = AccountForm()
    _populate_form_choices(form)
    return render_template("accounts.html", accounts=accounts, form=form)


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

        device_id = form.device_id.data

        account = Account(
            service=form.service.data,
            username=form.username.data,
            owner_id=form.owner_id.data,
            device_id=device_id,
            notes=form.notes.data,
        )
        account.set_password(password_plain)
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


@bp.route("/<int:account_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "technician")
def edit_account(account_id: int):
    account = Account.query.get_or_404(account_id)
    form = AccountForm(
        service=account.service,
        username=account.username,
        owner_id=account.owner_id,
        device_id=account.device_id or 0,
        notes=account.notes,
    )
    _populate_form_choices(form)

    if request.method == "POST":
        if form.validate_on_submit():
            password_plain = form.password.data
            if _password_is_reused(password_plain, exclude_account_id=account.id):
                flash("La contrasena ya esta siendo utilizada por otra cuenta.", "warning")
                return redirect(url_for("accounts.edit_account", account_id=account.id))

            account.service = form.service.data
            account.username = form.username.data
            account.owner_id = form.owner_id.data
            device_id = form.device_id.data
            account.device_id = device_id
            account.notes = form.notes.data
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
    db.session.delete(account)
    db.session.commit()
    flash("Cuenta eliminada.", "info")
    log_action("accounts.delete", metadata={"account_id": account_id})
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
