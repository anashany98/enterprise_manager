from datetime import date

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    DateField,
    HiddenField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp, ValidationError

ROLE_CHOICES = [
    ("admin", "Administrador"),
    ("technician", "Tecnico"),
    ("viewer", "Visualizacion"),
]

DEVICE_STATUS_CHOICES = [
    ("active", "Activo"),
    ("maintenance", "Mantenimiento"),
    ("retired", "Retirado"),
]


def optional_int_coerce(value):
    if value in (None, "", "None"):
        return None
    return int(value)


def password_complexity_validator(form, field):
    # Password complexity restrictions disabled per requirement.
    return


class LoginForm(FlaskForm):
    email = StringField("Correo electronico", validators=[DataRequired(), Email()])
    password = PasswordField("Contrasena", validators=[DataRequired()])
    remember = BooleanField("Recordarme")
    submit = SubmitField("Iniciar sesion")


class TwoFactorForm(FlaskForm):
    token = StringField(
        "Codigo de verificacion",
        validators=[DataRequired(), Regexp(r"^\d{6}$", message="Ingrese un codigo de 6 digitos.")],
    )
    submit = SubmitField("Verificar")


class UserForm(FlaskForm):
    id = HiddenField()
    name = StringField("Nombre completo", validators=[DataRequired(), Length(max=120)])
    position = StringField("Cargo", validators=[Optional(), Length(max=120)])
    email = StringField("Correo electronico", validators=[DataRequired(), Email(), Length(max=255)])
    phone = StringField("Telefono", validators=[Optional(), Length(max=50)])
    country = StringField("Pais", validators=[Optional(), Length(max=120)])
    location = StringField("Ubicacion", validators=[Optional(), Length(max=120)])
    active = BooleanField("Activo", default=True)
    notes = TextAreaField("Notas", validators=[Optional()])
    role = SelectField("Rol", validators=[DataRequired()], choices=ROLE_CHOICES)
    password = PasswordField(
        "Contrasena",
        validators=[Optional(), password_complexity_validator],
        description="Dejar vacio para mantener la contrasena actual",
    )
    confirm_password = PasswordField(
        "Confirmar contrasena",
        validators=[
            Optional(),
            EqualTo("password", message="Las contrasenas no coinciden."),
        ],
    )
    submit = SubmitField("Guardar usuario")


class DeviceForm(FlaskForm):
    type = StringField("Tipo de dispositivo", validators=[DataRequired(), Length(max=120)])
    brand = StringField("Marca", validators=[Optional(), Length(max=120)])
    model = StringField("Modelo", validators=[Optional(), Length(max=120)])
    serial_number = StringField("Numero de serie", validators=[DataRequired(), Length(max=120)])
    purchase_date = DateField(
        "Fecha de compra",
        validators=[Optional()],
        default=date.today,
        format="%Y-%m-%d",
    )
    country = StringField("Pais", validators=[Optional(), Length(max=120)])
    location = StringField("Ubicacion", validators=[Optional(), Length(max=120)])
    assigned_user_id = SelectField("Usuario asignado", coerce=int, validators=[Optional()])
    status = SelectField("Estado", validators=[DataRequired()], choices=DEVICE_STATUS_CHOICES)
    notes = TextAreaField("Notas", validators=[Optional()])
    submit = SubmitField("Guardar dispositivo")


class AccountForm(FlaskForm):
    service = StringField("Servicio", validators=[DataRequired(), Length(max=120)])
    username = StringField("Usuario", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Contrasena", validators=[DataRequired(), password_complexity_validator])
    confirm_password = PasswordField(
        "Confirmar contrasena",
        validators=[DataRequired(), EqualTo("password", message="Las contrasenas no coinciden.")],
    )
    owner_id = SelectField("Propietario", coerce=int, validators=[DataRequired()])
    device_id = SelectField("Dispositivo", coerce=optional_int_coerce, validators=[Optional()])
    notes = TextAreaField("Notas", validators=[Optional()])
    submit = SubmitField("Guardar cuenta")


class AccountFilterForm(FlaskForm):
    country = SelectField("Pais", choices=[], validators=[Optional()])
    location = SelectField("Ubicacion", choices=[], validators=[Optional()])
    status = SelectField("Estado", choices=[], validators=[Optional()])
    owner_id = SelectField("Propietario", coerce=int, choices=[], validators=[Optional()])
    submit = SubmitField("Filtrar")
