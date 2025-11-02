import base64
import datetime as dt
import os
from typing import Optional

import bcrypt
import pyotp
from flask import current_app
from flask_login import LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, func
from sqlalchemy.orm import validates

from crypto_utils import decrypt_password, encrypt_password

db = SQLAlchemy()
login_manager = LoginManager()


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=dt.datetime.utcnow,
        onupdate=dt.datetime.utcnow,
        nullable=False,
    )


class User(UserMixin, TimestampMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    position = db.Column(db.String(120))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(50))
    country = db.Column(db.String(120))
    location = db.Column(db.String(120))
    active = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.Text)
    password_hash = db.Column(db.LargeBinary(128), nullable=False)
    role = db.Column(db.String(50), default="viewer", nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    last_login_at = db.Column(db.DateTime)

    devices = db.relationship("Device", back_populates="assigned_user", lazy="dynamic")
    accounts = db.relationship("Account", back_populates="owner", lazy="dynamic")
    logs = db.relationship("Log", back_populates="user", lazy="dynamic")

    def get_id(self) -> str:
        return str(self.id)

    @property
    def is_active(self) -> bool:  # type: ignore[override]
        return self.active

    def set_password(self, password: str) -> None:
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash)

    def enable_totp(self) -> str:
        secret = base64.b32encode(os.urandom(10)).decode("utf-8").strip("=")
        self.totp_secret = secret
        return secret

    def disable_totp(self) -> None:
        self.totp_secret = None

    def verify_totp(self, token: str) -> bool:
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "position": self.position,
            "email": self.email,
            "phone": self.phone,
            "country": self.country,
            "location": self.location,
            "active": self.active,
            "role": self.role,
            "notes": self.notes,
        }

    @validates("role")
    def validate_role(self, key, value):
        allowed = {"admin", "technician", "viewer"}
        if value not in allowed:
            raise ValueError(
                f"Invalid role '{value}'. Allowed roles: {', '.join(sorted(allowed))}"
            )
        return value


class Device(TimestampMixin, db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(120), nullable=False)
    brand = db.Column(db.String(120))
    model = db.Column(db.String(120))
    serial_number = db.Column(db.String(120), unique=True, nullable=False)
    purchase_date = db.Column(db.Date)
    country = db.Column(db.String(120))
    location = db.Column(db.String(120))
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    status = db.Column(db.String(120), default="active")
    notes = db.Column(db.Text)

    assigned_user = db.relationship("User", back_populates="devices")
    accounts = db.relationship("Account", back_populates="device", lazy="dynamic")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "brand": self.brand,
            "model": self.model,
            "serial_number": self.serial_number,
            "purchase_date": self.purchase_date.isoformat()
            if self.purchase_date
            else None,
            "country": self.country,
            "location": self.location,
            "assigned_user_id": self.assigned_user_id,
            "status": self.status,
            "notes": self.notes,
        }


class Account(TimestampMixin, db.Model):
    __tablename__ = "accounts"

    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"))
    notes = db.Column(db.Text)
    last_modified = db.Column(
        db.DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )

    owner = db.relationship("User", back_populates="accounts")
    device = db.relationship("Device", back_populates="accounts")

    def set_password(self, password: str) -> None:
        self.password_encrypted = encrypt_password(password)

    def get_password(self) -> str:
        return decrypt_password(self.password_encrypted)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service": self.service,
            "username": self.username,
            "owner_id": self.owner_id,
            "device_id": self.device_id,
            "notes": self.notes,
            "last_modified": self.last_modified.isoformat()
            if self.last_modified
            else None,
        }


class Log(TimestampMixin, db.Model):
    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(64))
    meta_data = db.Column(db.JSON)  # <-- nombre corregido
    occurred_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)

    user = db.relationship("User", back_populates="logs")


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    if not user_id:
        return None
    return User.query.get(int(user_id))


def _normalize_email(target, value, oldvalue, initiator):  # pragma: no cover - SQLAlchemy hook
    return value.lower() if value else value


event.listen(User.email, "set", _normalize_email, retval=True)


def create_default_admin() -> None:
    """Ensure the default administrator exists on startup."""
    admin_email = current_app.config.get("ADMIN_EMAIL")
    admin_password = current_app.config.get("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        return

    existing = User.query.filter(func.lower(User.email) == admin_email.lower()).first()
    if existing:
        return

    admin = User(
        name="Administrator",
        position="System Administrator",
        email=admin_email,
        role="admin",
        active=True,
    )
    admin.set_password(admin_password)
    db.session.add(admin)
    db.session.commit()
