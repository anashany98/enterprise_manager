from datetime import datetime

import pyotp
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from forms import LoginForm, TwoFactorForm
from models import User, db
from utils import log_action

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email == form.email.data.lower()).first()
        if user is None or not user.check_password(form.password.data):
            flash("Credenciales no validas.", "danger")
            log_action(
                "auth.login_failed",
                metadata={"email": form.email.data.lower()},
            )
            return redirect(url_for("auth.login"))

        if not user.active:
            flash("Su cuenta esta deshabilitada. Contacte al administrador.", "warning")
            log_action("auth.login_inactive", metadata={"user_id": user.id})
            return redirect(url_for("auth.login"))

        session["pre_2fa_user_id"] = user.id
        session["login_remember"] = form.remember.data
        if user.totp_secret:
            return redirect(url_for("auth.two_factor"))

        login_user(user, remember=form.remember.data)
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        log_action("auth.login_success")
        return redirect(url_for("main.dashboard"))

    return render_template("login.html", form=form)


@bp.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user or not user.totp_secret:
        return redirect(url_for("auth.login"))

    form = TwoFactorForm()
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            remember = session.pop("login_remember", False)
            session.pop("pre_2fa_user_id", None)
            login_user(user, remember=remember)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            log_action("auth.2fa_success")
            return redirect(url_for("main.dashboard"))

        flash("Codigo 2FA invalido.", "danger")
        log_action("auth.2fa_failed", metadata={"user_id": user.id})

    return render_template("two_factor.html", form=form, email=user.email)


@bp.route("/logout")
@login_required
def logout():
    log_action("auth.logout")
    logout_user()
    session.clear()
    flash("Sesion cerrada correctamente.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/two-factor/setup")
@login_required
def setup_two_factor():
    if current_user.totp_secret:
        flash("El doble factor ya esta configurado.", "info")
        return redirect(url_for("main.dashboard"))

    secret = current_user.enable_totp()
    db.session.commit()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="Enterprise Manager",
    )
    log_action("auth.2fa_enabled")
    return render_template(
        "two_factor_setup.html",
        secret=secret,
        provisioning_uri=provisioning_uri,
    )


@bp.route("/two-factor/disable", methods=["POST"])
@login_required
def disable_two_factor():
    if not current_user.totp_secret:
        flash("El doble factor no estaba configurado.", "warning")
        return redirect(url_for("main.dashboard"))

    current_user.disable_totp()
    db.session.commit()
    log_action("auth.2fa_disabled")
    flash("2FA deshabilitado correctamente.", "info")
    return redirect(url_for("main.dashboard"))
