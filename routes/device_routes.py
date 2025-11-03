from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from sqlalchemy.orm import joinedload

from forms import DEVICE_BRAND_MAP, DEVICE_OS_MAP, DeviceForm
from models import Device, User, db
from utils import log_action, role_required

bp = Blueprint("devices", __name__, url_prefix="/devices")


def _populate_form_choices(form: DeviceForm) -> None:
    users = User.query.filter_by(active=True).order_by(User.name.asc()).all()
    choices = [(0, "Sin asignar")] + [(user.id, user.name) for user in users]
    form.assigned_user_id.choices = choices


@bp.route("/", methods=["GET"])
@login_required
def list_devices():
    devices = (
        Device.query.order_by(Device.created_at.desc())
        .options(joinedload(Device.assigned_user))
        .all()
    )
    form = DeviceForm()
    _populate_form_choices(form)
    return render_template(
        "devices.html",
        devices=devices,
        form=form,
        device_brand_map=DEVICE_BRAND_MAP,
        device_os_map=DEVICE_OS_MAP,
    )


@bp.route("/create", methods=["POST"])
@login_required
@role_required("admin", "technician")
def create_device():
    form = DeviceForm()
    _populate_form_choices(form)
    if form.validate_on_submit():
        assigned_user_id = form.assigned_user_id.data or None
        if assigned_user_id == 0:
            assigned_user_id = None

        brand_value = (form.brand.data or "").strip()
        operating_system = (form.operating_system.data or "").strip()
        ip_address = (form.ip_address.data or "").strip()

        device = Device(
            type=form.type.data,
            category=form.category.data,
            brand=brand_value or None,
            model=form.model.data,
            serial_number=form.serial_number.data,
            purchase_date=form.purchase_date.data,
            country=form.country.data,
            location=form.location.data,
            ip_address=ip_address or None,
            operating_system=operating_system or None,
            assigned_user_id=assigned_user_id,
            status=form.status.data,
            notes=form.notes.data,
        )
        db.session.add(device)
        db.session.commit()
        flash("Dispositivo creado correctamente.", "success")
        log_action("devices.create", metadata={"device_id": device.id})
    else:
        flash("Error al crear el dispositivo.", "danger")
    return redirect(url_for("devices.list_devices"))


@bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin", "technician")
def edit_device(device_id: int):
    device = Device.query.get_or_404(device_id)
    form = DeviceForm(obj=device)
    _populate_form_choices(form)

    if request.method == "POST":
        if form.validate_on_submit():
            device.type = form.type.data
            device.category = form.category.data
            brand_value = (form.brand.data or "").strip()
            device.brand = brand_value or None
            device.model = form.model.data
            device.serial_number = form.serial_number.data
            device.purchase_date = form.purchase_date.data
            device.country = form.country.data
            device.location = form.location.data
            device.ip_address = (form.ip_address.data or "").strip() or None
            operating_system = (form.operating_system.data or "").strip()
            device.operating_system = operating_system or None
            assigned_user_id = form.assigned_user_id.data or None
            if assigned_user_id == 0:
                assigned_user_id = None
            device.assigned_user_id = assigned_user_id
            device.status = form.status.data
            device.notes = form.notes.data

            db.session.commit()
            flash("Dispositivo actualizado.", "success")
            log_action("devices.update", metadata={"device_id": device.id})
            return redirect(url_for("devices.list_devices"))

        flash("Error al actualizar el dispositivo.", "danger")

    if device.assigned_user_id is None:
        form.assigned_user_id.data = 0
    return render_template(
        "device_edit.html",
        device=device,
        form=form,
        device_brand_map=DEVICE_BRAND_MAP,
        device_os_map=DEVICE_OS_MAP,
    )


@bp.route("/<int:device_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_device(device_id: int):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash("Dispositivo eliminado.", "info")
    log_action("devices.delete", metadata={"device_id": device_id})
    return redirect(url_for("devices.list_devices"))
