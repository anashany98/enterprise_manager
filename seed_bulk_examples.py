import datetime as dt
import random
import string

from app import app
from models import Account, Device, User, db


COUNTRIES = [
    "Spain",
    "Mexico",
    "Argentina",
    "Chile",
    "Colombia",
    "Peru",
    "United States",
    "Portugal",
]

LOCATIONS = [
    "Madrid",
    "Barcelona",
    "Valencia",
    "Sevilla",
    "Bilbao",
    "Lisboa",
    "Ciudad de Mexico",
    "Buenos Aires",
    "Santiago",
    "Bogota",
    "Lima",
]

CATEGORY_DETAILS = {
    "computer": {
        "types": ["Laptop", "Desktop", "Workstation", "Mini PC"],
        "brands": ["Lenovo", "Dell", "HP", "Asus", "MSI", "Acer", "Apple", "Gigabyte"],
        "operating_systems": ["Windows 11", "Windows 10", "Ubuntu 22.04", "Debian 12", "ChromeOS"],
    },
    "mobile": {
        "types": ["Smartphone", "Phone"],
        "brands": ["Samsung", "Apple", "Google", "Xiaomi", "OnePlus", "Huawei", "Motorola"],
        "operating_systems": ["Android 14", "Android 13", "iOS 17", "HarmonyOS"],
    },
    "tablet": {
        "types": ["Tablet"],
        "brands": ["Apple", "Samsung", "Lenovo", "Microsoft", "Huawei"],
        "operating_systems": ["iPadOS 17", "Android 14", "Windows 11", "ChromeOS"],
    },
    "peripheral": {
        "types": ["Printer", "Scanner", "Router", "Monitor"],
        "brands": ["HP", "Brother", "Canon", "Epson", "Lexmark", "Cisco", "BenQ", "LG"],
        "operating_systems": ["Firmware propietario", "Otro"],
    },
}

STATUS_CHOICES = ["active", "maintenance", "retired", "damaged"]
SERVICE_NAMES = [
    "Salesforce",
    "GitHub",
    "Jira",
    "Slack",
    "Confluence",
    "PostgreSQL",
    "MongoDB Atlas",
    "AWS Console",
    "Azure Portal",
    "GCP Console",
    "Bitbucket",
    "Zendesk",
    "Notion",
    "HubSpot",
    "ServiceNow",
    "Grafana",
    "Prometheus",
    "Vault",
    "Okta",
    "1Password",
]

FIRST_NAMES = [
    "Ana",
    "Luis",
    "Maria",
    "Javier",
    "Sofia",
    "Carlos",
    "Laura",
    "Miguel",
    "Lucia",
    "Andres",
    "Paula",
    "Diego",
    "Elena",
    "Fernando",
    "Irene",
]

LAST_NAMES = [
    "Gomez",
    "Lopez",
    "Martinez",
    "Rodriguez",
    "Fernandez",
    "Hernandez",
    "Sanchez",
    "Ramirez",
    "Torres",
    "Diaz",
    "Castro",
    "Morales",
    "Vargas",
    "Reyes",
    "Mendoza",
]


def random_date(start_year: int = 2020) -> dt.date:
    start = dt.date(start_year, 1, 1)
    end = dt.date.today()
    delta = (end - start).days
    return start + dt.timedelta(days=random.randint(0, max(delta, 1)))


def generate_password():
    letters = string.ascii_letters
    digits = string.digits
    special = "!@#$%&*"
    return (
        random.choice(letters).upper()
        + random.choice(letters).lower()
        + random.choice(digits)
        + random.choice(special)
        + "".join(random.choice(letters + digits) for _ in range(4))
    )


def create_demo_users(desired_count: int = 20) -> list[User]:
    created_users: list[User] = []
    suffix = 1
    while len(created_users) < desired_count:
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        email = f"demo_user_{suffix}@example.com"
        suffix += 1
        if User.query.filter_by(email=email).first():
            continue
        user = User(
            name=f"{first} {last}",
            position=random.choice(["Analista", "Tecnico", "Administrador", "Operador"]),
            email=email,
            phone=f"+34 600 {random.randint(100000, 999999)}",
            country=random.choice(COUNTRIES),
            location=random.choice(LOCATIONS),
            role=random.choice(["viewer", "technician", "admin"]),
            active=True,
        )
        user.set_password(generate_password())
        db.session.add(user)
        created_users.append(user)
    db.session.flush()
    return created_users


def create_demo_devices(desired_count: int, users: list[User]) -> list[Device]:
    created_devices: list[Device] = []
    suffix = 1
    while len(created_devices) < desired_count:
        serial = f"DEMO-{suffix:05d}"
        suffix += 1
        if Device.query.filter_by(serial_number=serial).first():
            continue
        category = random.choice(list(CATEGORY_DETAILS.keys()))
        details = CATEGORY_DETAILS[category]
        device = Device(
            type=random.choice(details["types"]),
            category=category,
            brand=random.choice(details["brands"]),
            model=f"Model-{random.randint(100, 999)}",
            serial_number=serial,
            purchase_date=random_date(),
            country=random.choice(COUNTRIES),
            location=random.choice(LOCATIONS),
            ip_address=f"10.{random.randint(0, 10)}.{random.randint(0, 250)}.{random.randint(1, 254)}",
            operating_system=random.choice(details["operating_systems"]),
            assigned_user=random.choice(users + [None]),
            status=random.choice(STATUS_CHOICES),
            notes="Equipo de ejemplo generado automaticamente.",
        )
        db.session.add(device)
        created_devices.append(device)
    db.session.flush()
    return created_devices


def create_demo_accounts(desired_count: int, users: list[User], devices: list[Device]) -> list[Account]:
    if not users or not devices:
        return []
    created_accounts: list[Account] = []
    suffix = 1
    device_pool = devices.copy()
    while len(created_accounts) < desired_count:
        owner = random.choice(users)
        service_name = random.choice(SERVICE_NAMES)
        service = f"{service_name} {suffix}"
        suffix += 1
        if Account.query.filter_by(service=service, username=owner.email).first():
            continue
        account = Account(
            service=service,
            username=f"{owner.email.split('@')[0]}.{random.randint(1, 99):02d}",
            owner=owner,
            notes="Cuenta generada para demostracion.",
            country=random.choice(COUNTRIES),
            location=random.choice(LOCATIONS),
            active=random.random() > 0.15,
        )
        account.set_password(generate_password())
        num_devices = random.randint(1, min(3, len(device_pool)))
        account.devices = random.sample(device_pool, num_devices)
        db.session.add(account)
        created_accounts.append(account)
    db.session.flush()
    return created_accounts


def main() -> None:
    USER_TARGET = 200
    DEVICE_TARGET = 400
    ACCOUNT_TARGET = 400

    with app.app_context():
        users = create_demo_users(USER_TARGET)
        devices = create_demo_devices(DEVICE_TARGET, users)
        accounts = create_demo_accounts(ACCOUNT_TARGET, users, devices)
        db.session.commit()
        print(
            f"Sample data inserted: {len(users)} users, {len(devices)} devices, {len(accounts)} accounts "
            f"(total {len(users)+len(devices)+len(accounts)} records)."
        )


if __name__ == "__main__":
    main()
