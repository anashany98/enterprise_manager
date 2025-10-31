from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..forms import UserForm
from ..models import User, db
from ..utils import log_action, role_required

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.route("/", methods=["GET"])
@login_required
def list_users():
    users = User.query.order_by(User.name.asc()).all()
    form = UserForm()
    return render_template("users.html", users=users, form=form)


@bp.route("/create", methods=["POST"])
@login_required
@role_required("admin")
def create_user():
    form = UserForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Ya existe un usuario con ese correo electronico.", "danger")
            return redirect(url_for("users.list_users"))

        user = User(
            name=form.name.data,
            position=form.position.data,
            email=form.email.data.lower(),
            phone=form.phone.data,
            country=form.country.data,
            location=form.location.data,
            notes=form.notes.data,
            role=form.role.data,
            active=form.active.data,
        )
        if form.password.data:
            user.set_password(form.password.data)
        else:
            flash("Debe establecer una contrasena para el nuevo usuario.", "danger")
            return redirect(url_for("users.list_users"))

        db.session.add(user)
        db.session.commit()
        flash("Usuario creado correctamente.", "success")
        log_action("users.create", metadata={"user_id": user.id})
    else:
        flash("Error al crear el usuario. Revise el formulario.", "danger")

    return redirect(url_for("users.list_users"))


@bp.route("/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def edit_user(user_id: int):
    user = User.query.get_or_404(user_id)
    if current_user.role != "admin" and current_user.id != user.id:
        flash("No tiene permisos para editar este usuario.", "danger")
        return redirect(url_for("users.list_users"))

    form = UserForm(obj=user)
    if request.method == "POST":
        if form.validate_on_submit():
            if (
                form.email.data.lower() != user.email
                and User.query.filter_by(email=form.email.data.lower()).first()
            ):
                flash("El correo ya esta en uso por otro usuario.", "danger")
                return redirect(url_for("users.edit_user", user_id=user.id))

            user.name = form.name.data
            user.position = form.position.data
            user.email = form.email.data.lower()
            user.phone = form.phone.data
            user.country = form.country.data
            user.location = form.location.data
            user.notes = form.notes.data
            user.role = form.role.data
            user.active = form.active.data

            if form.password.data:
                user.set_password(form.password.data)

            db.session.commit()
            flash("Usuario actualizado correctamente.", "success")
            log_action("users.update", metadata={"user_id": user.id})
            return redirect(url_for("users.list_users"))

        flash("Error al actualizar el usuario.", "danger")

    form.password.data = ""
    form.confirm_password.data = ""
    return render_template("user_edit.html", form=form, user=user)


@bp.route("/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id: int):
    if current_user.id == user_id:
        flash("No puede eliminar su propio usuario mientras esta conectado.", "warning")
        return redirect(url_for("users.list_users"))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado.", "info")
    log_action("users.delete", metadata={"user_id": user_id})
    return redirect(url_for("users.list_users"))
