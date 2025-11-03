import datetime as dt

from app import app
from models import Account, Device, Log, User, db


def ensure_users() -> dict[str, User]:
    """Create a set of demo users if they do not exist."""
    users_data = [
        {
            "name": "Ana Gomez",
            "email": "ana.gomez@example.com",
            "position": "IT Specialist",
            "role": "technician",
            "password": "Ana2024!",
            "phone": "+34 600 111 222",
            "country": "Spain",
            "location": "Madrid",
            "notes": "Responsable del soporte tecnologico regional.",
        },
        {
            "name": "Luis Martinez",
            "email": "luis.martinez@example.com",
            "position": "Operations Manager",
            "role": "viewer",
            "password": "LuisOps2024!",
            "phone": "+34 600 333 444",
            "country": "Spain",
            "location": "Barcelona",
            "notes": "Coordina las operaciones diarias y revisa informes.",
        },
        {
            "name": "Maria Rodriguez",
            "email": "maria.rodriguez@example.com",
            "position": "Security Lead",
            "role": "admin",
            "password": "MariaSec2024!",
            "phone": "+34 600 555 666",
            "country": "Spain",
            "location": "Valencia",
            "notes": "Encargada de las politicas de seguridad y auditoria.",
        },
    ]

    created_users: dict[str, User] = {}
    for data in users_data:
        email = data["email"].lower()
        user = User.query.filter_by(email=email).first()
        if user:
            created_users[email] = user
            continue

        user = User(
            name=data["name"],
            email=email,
            position=data["position"],
            role=data["role"],
            phone=data["phone"],
            country=data["country"],
            location=data["location"],
            notes=data["notes"],
            active=True,
        )
        user.set_password(data["password"])
        db.session.add(user)
        created_users[email] = user

    return created_users


def ensure_devices(user_lookup: dict[str, User]) -> dict[str, Device]:
    """Create sample devices and assign them to demo users."""
    devices_data = [
        {
            "type": "Laptop",
            "category": "computer",
            "brand": "Lenovo",
            "model": "ThinkPad X1 Carbon",
            "serial_number": "LN-TPX1-001",
            "purchase_date": dt.date(2023, 2, 14),
            "country": "Spain",
            "location": "Madrid",
            "operating_system": "Windows 11 Pro",
            "ip_address": "10.0.0.21",
            "status": "active",
            "notes": "Equipo principal de Ana para soporte remoto.",
            "assigned_to": "ana.gomez@example.com",
        },
        {
            "type": "Tablet",
            "category": "tablet",
            "brand": "Apple",
            "model": "iPad Pro 11\"",
            "serial_number": "AP-IP11-742",
            "purchase_date": dt.date(2022, 11, 3),
            "country": "Spain",
            "location": "Barcelona",
            "operating_system": "iPadOS 17",
            "ip_address": "10.0.1.42",
            "status": "maintenance",
            "notes": "Dispositivo de control de inventario de Luis.",
            "assigned_to": "luis.martinez@example.com",
        },
        {
            "type": "Smartphone",
            "category": "mobile",
            "brand": "Samsung",
            "model": "Galaxy S23",
            "serial_number": "SM-GS23-555",
            "purchase_date": dt.date(2024, 4, 19),
            "country": "Spain",
            "location": "Valencia",
            "operating_system": "Android 14",
            "ip_address": "10.0.2.55",
            "status": "active",
            "notes": "Telefono dedicado a alertas de seguridad.",
            "assigned_to": "maria.rodriguez@example.com",
        },
    ]

    created_devices: dict[str, Device] = {}
    for data in devices_data:
        serial = data["serial_number"]
        device = Device.query.filter_by(serial_number=serial).first()
        if device:
            created_devices[serial] = device
            continue

        assigned_user = user_lookup.get(data["assigned_to"].lower())
        device = Device(
            type=data["type"],
            category=data.get("category", "computer"),
            brand=data["brand"],
            model=data["model"],
            serial_number=serial,
            purchase_date=data["purchase_date"],
            country=data["country"],
            location=data["location"],
            ip_address=data.get("ip_address"),
            operating_system=data["operating_system"],
            status=data["status"],
            notes=data["notes"],
            assigned_user=assigned_user,
        )
        db.session.add(device)
        created_devices[serial] = device

    return created_devices


def ensure_accounts(user_lookup: dict[str, User], device_lookup: dict[str, Device]) -> None:
    """Create demo service accounts linked to users and devices."""
    accounts_data = [
        {
            "service": "Salesforce",
            "username": "ana.gomez",
            "owner": "ana.gomez@example.com",
            "device_serials": ["LN-TPX1-001", "SM-GS23-555"],
            "password": "SfAccount#1",
            "notes": "Acceso al CRM para gestionar incidencias de clientes.",
            "country": "Spain",
            "location": "Madrid",
            "active": True,
        },
        {
            "service": "Grafana",
            "username": "luis.martinez",
            "owner": "luis.martinez@example.com",
            "device_serials": ["AP-IP11-742"],
            "password": "GrafanaView2024",
            "notes": "Panel de seguimiento de indicadores operativos.",
            "country": "Spain",
            "location": "Barcelona",
            "active": True,
        },
        {
            "service": "Vault",
            "username": "maria.rodriguez",
            "owner": "maria.rodriguez@example.com",
            "device_serials": ["SM-GS23-555"],
            "password": "VaultSecure!",
            "notes": "Credenciales para revisar registros de auditoria.",
            "country": "Spain",
            "location": "Valencia",
            "active": True,
        },
    ]

    for data in accounts_data:
        owner_email = data["owner"].lower()
        existing = (
            Account.query.filter_by(service=data["service"], username=data["username"]).first()
        )
        if existing:
            continue

        owner = user_lookup.get(owner_email)

        account = Account(
            service=data["service"],
            username=data["username"],
            owner=owner,
            notes=data["notes"],
            country=data.get("country"),
            location=data.get("location"),
            active=data.get("active", True),
        )
        account.set_password(data["password"])
        serials = data.get("device_serials", [])
        if serials:
            account.devices = [
                device_lookup[serial]
                for serial in serials
                if serial in device_lookup
            ]
        db.session.add(account)


def ensure_logs(user_lookup: dict[str, User]) -> None:
    """Add a handful of activity logs to make the dashboard livelier."""
    log_entries = [
        {
            "action": "user.login",
            "user": "ana.gomez@example.com",
            "ip": "192.168.10.24",
            "meta": {"result": "success"},
        },
        {
            "action": "device.update_status",
            "user": "maria.rodriguez@example.com",
            "ip": "192.168.10.42",
            "meta": {"device": "SM-GS23-555", "status": "active"},
        },
        {
            "action": "account.password_reset",
            "user": "maria.rodriguez@example.com",
            "ip": "192.168.10.42",
            "meta": {"service": "Vault"},
        },
        {
            "action": "report.export",
            "user": "luis.martinez@example.com",
            "ip": "192.168.10.30",
            "meta": {"report": "operaciones_mensual"},
        },
    ]

    for entry in log_entries:
        user = user_lookup.get(entry["user"])
        if not user:
            continue
        log = Log(
            action=entry["action"],
            user=user,
            ip_address=entry["ip"],
            meta_data=entry["meta"],
            occurred_at=dt.datetime.utcnow(),
        )
        db.session.add(log)


def main() -> None:
    with app.app_context():
        user_lookup = ensure_users()
        db.session.flush()

        device_lookup = ensure_devices(user_lookup)
        db.session.flush()

        ensure_accounts(user_lookup, device_lookup)
        ensure_logs(user_lookup)

        db.session.commit()
        print("Sample data ensured successfully.")


if __name__ == "__main__":
    main()
