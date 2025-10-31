# Enterprise Manager (PsswdINV)

Aplicacion web construida con Flask para administrar usuarios, dispositivos y credenciales corporativas con cifrado AES-256 y controles de auditoria.

## Requisitos

- Python 3.11 o superior
- pip y virtualenv
- (Opcional) Docker y Docker Compose

## Instalacion local

```bash
python -m venv venv
venv\Scripts\activate  # En PowerShell
pip install -r requirements.txt
```

## Configuracion de variables de entorno

Crea un archivo `.env` (ya se incluye un ejemplo) con los valores necesarios:

- `FLASK_ENV`: `development` o `production`
- `SECRET_KEY`: clave secreta de Flask
- `ENCRYPTION_KEY`: clave base64 de 32 bytes para AES-GCM
- `DATABASE_URL`: `sqlite:///empresa.db` u otra conexion compatible con SQLAlchemy
- `ADMIN_EMAIL` / `ADMIN_PASSWORD`: credenciales iniciales
- `JWT_SECRET_KEY`: clave para emitir tokens de la API

Para generar una clave de cifrado segura:

```python
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
```

## Ejecucion en desarrollo

```bash
venv\Scripts\activate
python -m enterprise_manager.app  # tambien puedes usar: flask --app enterprise_manager.app run
```

La primera vez que arranque se creara el usuario administrador definido en `.env` y la base de datos `empresa.db`.

## Copias de seguridad

- El sistema genera copias cifradas en `backups/` cada 24 horas (configurable con `DATABASE_BACKUP_INTERVAL_HOURS`).
- Cada archivo `.zip.enc` contiene una copia comprimida y cifrada de la base de datos.
- Para restaurar, usa el comando `flask shell` y ejecuta:

```python
from app import restore_backup
from pathlib import Path
restore_backup(Path('backups/archivo.zip.enc'))
```

## API REST segura

- Solicita un token con `POST /api/token` enviando JSON `{ "email": "...", "password": "..." }`.
- Usa el token recibido en el encabezado `Authorization: Bearer <token>` para consultar `/api/stats` y `/api/accounts`.

## Uso con Docker

```bash
docker compose up --build
```

Servicios incluidos:

1. `web`: contenedor Flask ejecutando Gunicorn.
2. `db`: PostgreSQL opcional (ajusta `DATABASE_URL`).
3. `nginx`: proxy inverso con HTTPS (coloca tus certificados en `deploy/certs/`).

## Recomendaciones de seguridad

- Cambia todas las claves por defecto antes de desplegar.
- Utiliza HTTPS en produccion.
- Habilita 2FA para administradores (`/two-factor/setup`).
- Revisa el registro de auditoria en `/logs`.
- Programa rotacion de contrasenas y monitorea las exportaciones.

## Tareas futuras sugeridas

- Migrar la API a FastAPI y JWT con refresh tokens.
- Anadir autenticacion externa (LDAP, Google Workspace).
- Implementar pruebas automatizadas con pytest y CI/CD.
- Incorporar soporte multiempresa y permisos avanzados.
