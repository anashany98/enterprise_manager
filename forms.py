from datetime import date

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    DateField,
    HiddenField,
    PasswordField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
)
from flask_wtf.file import FileAllowed, FileField, FileRequired
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
    ("damaged", "Danado"),
]

DEVICE_CATEGORY_CHOICES = [
    ("computer", "Ordenador"),
    ("mobile", "Movil"),
    ("tablet", "Tablet"),
    ("peripheral", "Periferico"),
]

DEVICE_BRAND_MAP = {
    "computer": [
        ("Acer", "Acer"),
        ("Alienware", "Alienware"),
        ("Asus", "Asus"),
        ("Dell", "Dell"),
        ("Gigabyte", "Gigabyte"),
        ("HP", "HP"),
        ("Lenovo", "Lenovo"),
        ("LG", "LG"),
        ("Microsoft", "Microsoft"),
        ("MSI", "MSI"),
        ("Razer", "Razer"),
        ("Samsung", "Samsung"),
        ("Sony", "Sony"),
        ("Toshiba", "Toshiba"),
    ],
    "mobile": [
        ("Apple", "Apple"),
        ("Google", "Google"),
        ("Huawei", "Huawei"),
        ("Motorola", "Motorola"),
        ("Nokia", "Nokia"),
        ("OnePlus", "OnePlus"),
        ("Oppo", "Oppo"),
        ("Realme", "Realme"),
        ("Samsung", "Samsung"),
        ("Xiaomi", "Xiaomi"),
        ("ZTE", "ZTE"),
    ],
    "tablet": [
        ("Apple", "Apple"),
        ("Lenovo", "Lenovo"),
        ("Huawei", "Huawei"),
        ("Samsung", "Samsung"),
        ("Microsoft", "Microsoft"),
    ],
    "peripheral": [
        ("Brother", "Brother"),
        ("Canon", "Canon"),
        ("Epson", "Epson"),
        ("HP", "HP"),
        ("Kyocera", "Kyocera"),
        ("Lexmark", "Lexmark"),
        ("Ricoh", "Ricoh"),
        ("Xerox", "Xerox"),
        ("Otra marca", "Otra marca"),
    ],
}

DEVICE_OS_MAP = {
    "computer": [
        ("Windows", "Windows"),
        ("macOS", "macOS"),
        ("Linux", "Linux"),
        ("ChromeOS", "ChromeOS"),
        ("Otro", "Otro"),
    ],
    "mobile": [
        ("Android", "Android"),
        ("iOS / iPadOS", "iOS / iPadOS"),
        ("HarmonyOS", "HarmonyOS"),
        ("Otro", "Otro"),
    ],
    "tablet": [
        ("Android", "Android"),
        ("iOS / iPadOS", "iOS / iPadOS"),
        ("Windows", "Windows"),
        ("ChromeOS", "ChromeOS"),
        ("Otro", "Otro"),
    ],
    "peripheral": [
        ("Firmware propietario", "Firmware propietario"),
        ("Otro", "Otro"),
    ],
}


def _flatten_choice_map(choice_map: dict[str, list[tuple[str, str]]], default_label: str) -> list[tuple[str, str]]:
    ordered: dict[str, str] = {}
    for options in choice_map.values():
        for value, label in options:
            if value not in ordered:
                ordered[value] = label
    return [("", default_label)] + [(value, label) for value, label in ordered.items()]


DEVICE_BRAND_CHOICES = _flatten_choice_map(DEVICE_BRAND_MAP, "Seleccione una marca")
DEVICE_OS_CHOICES = _flatten_choice_map(DEVICE_OS_MAP, "Seleccione un sistema operativo")


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
    category = SelectField(
        "Categoria",
        choices=DEVICE_CATEGORY_CHOICES,
        validators=[DataRequired()],
        default="computer",
    )
    brand = SelectField(
        "Marca",
        choices=DEVICE_BRAND_CHOICES,
        validators=[Optional()],
        validate_choice=False,
    )
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
    ip_address = StringField(
        "Direccion IP",
        validators=[
            Optional(),
            Regexp(
                r"^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)$",
                message="Ingrese una direccion IP valida.",
            ),
        ],
    )
    operating_system = SelectField(
        "Sistema operativo",
        choices=DEVICE_OS_CHOICES,
        validators=[Optional()],
        validate_choice=False,
    )
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
    device_ids = SelectMultipleField("Dispositivos", coerce=int, validators=[Optional()])
    country = StringField("Pais", validators=[Optional(), Length(max=120)])
    location = StringField("Ubicacion", validators=[Optional(), Length(max=120)])
    active = BooleanField("Activo", default=True)
    notes = TextAreaField("Notas", validators=[Optional()])
    submit = SubmitField("Guardar cuenta")


class AccountFilterForm(FlaskForm):
    country = SelectField("Pais", choices=[], validators=[Optional()])
    location = SelectField("Ubicacion", choices=[], validators=[Optional()])
    status = SelectField("Estado", choices=[], validators=[Optional()])
    owner_id = SelectField("Propietario", coerce=int, choices=[], validators=[Optional()])
    submit = SubmitField("Filtrar")


class AccountImportForm(FlaskForm):
    file = FileField(
        "Archivo Excel",
        validators=[
            FileRequired(message="Seleccione un archivo para importar."),
            FileAllowed(["xlsx", "xls"], message="Solo se permiten archivos Excel (.xlsx, .xls)."),
        ],
    )
    submit = SubmitField("Importar cuentas")
