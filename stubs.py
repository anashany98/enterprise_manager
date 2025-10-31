"""Stub implementations for missing third-party dependencies.

This module provides minimal stand‑in versions of various third‑party
packages used by the Enterprise Manager application. When running in
restricted environments where installing the full dependencies isn't
possible, these stubs allow the rest of the code to import and run
without raising ``ModuleNotFoundError``. The goal of these stubs is
not to replicate full functionality but to provide just enough
structure for the application to start and basic unit tests to run.

To activate the stubs, call ``apply_stubs()`` near the top of your
application entry point. It will inspect the current environment and
register stub modules for any missing packages.

If full versions of the dependencies are available, the stubs are
ignored and the real packages will be used instead. This design makes
it safe to leave the call to ``apply_stubs()`` in production code;
it will silently do nothing when the real libraries are present.

Note: these stubs intentionally implement only a small subset of
attributes and methods referenced elsewhere in the codebase. If you
extend the application to use more features from the underlying
libraries, you may need to expand the stubs accordingly.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace


def apply_stubs() -> None:
    """Install stub modules for any third‑party dependencies that are not available.

    This function checks whether certain external packages can be
    imported. If an import fails, it constructs a minimal stub module
    providing the attributes used by the rest of the application and
    registers it in ``sys.modules``. Once registered, subsequent
    ``import`` statements will resolve to the stub instead of raising
    ``ModuleNotFoundError``.
    """

    def register_module(name: str, module: types.ModuleType) -> None:
        """Helper to register a module under a dotted name in ``sys.modules``.

        Because some stubs expose nested submodules (e.g.
        ``reportlab.lib.colors``), we need to ensure that each level
        exists in ``sys.modules``. This function handles creating
        intermediary parent packages automatically.

        Args:
            name: The fully qualified module name (e.g.
                ``"flask_login"`` or ``"reportlab.lib.colors"``).
            module: The module object to register.
        """
        parts = name.split(".")
        for i in range(1, len(parts)):
            pkg_name = ".".join(parts[:i])
            if pkg_name not in sys.modules:
                parent_pkg = types.ModuleType(pkg_name)
                sys.modules[pkg_name] = parent_pkg
        sys.modules[name] = module

    # ------------------------------------------------------------------
    # Flask and related stubs
    # ------------------------------------------------------------------
    try:
        import flask  # type: ignore  # noqa: F401
    except Exception:
        flask_mod = types.ModuleType("flask")

        class Flask:
            class _ConfigDict(dict):
                """Dictionary subclass with a ``from_object`` helper.

                The real Flask ``config`` object supports ``from_object`` to
                populate itself from an arbitrary class or object. This stub
                implementation copies all uppercase attributes from the
                provided object into the dictionary.
                """

                def from_object(self, obj) -> None:
                    for key in dir(obj):
                        if key.isupper():
                            self[key] = getattr(obj, key)

            def __init__(self, *args, **kwargs) -> None:
                # Basic application configuration dictionary with ``from_object``
                self.config: Flask._ConfigDict = Flask._ConfigDict()
                # Jinja environment placeholder used for registering filters
                self.jinja_env = SimpleNamespace(filters={})
                # Placeholder for WSGI app; unused in stubs
                self.wsgi_app = None

                # Debug flag (mirrors Flask's ``debug`` attribute)
                self.debug: bool = False

                # Provide a minimal CLI interface with a ``command`` decorator
                class _CLI:
                    def command(self, name: str):
                        # Return a decorator that simply returns the function unchanged
                        def decorator(func):
                            return func
                        return decorator

                self.cli = _CLI()

            def app_context(self):
                """Return a dummy application context manager.

                In real Flask applications ``app.app_context()`` provides
                a context for configuration and globals. This stub
                implementation simply returns a context manager that
                yields itself and performs no cleanup.
                """

                class _AppCtx:
                    def __enter__(self_nonlocal):  # type: ignore[override]
                        return self

                    def __exit__(self_nonlocal, exc_type, exc, tb) -> bool:
                        return False

                return _AppCtx()

            def route(self, *args, **kwargs):
                # Return a decorator that simply returns the function unchanged
                def decorator(func):
                    return func

                return decorator

            def register_blueprint(self, blueprint, *args, **kwargs) -> None:
                # No‑op for registering blueprints in stubs
                return None

            def context_processor(self, func):  # type: ignore[override]
                # Decorator for injecting context; simply returns the function
                return func

            def run(self, *args, **kwargs) -> None:
                # Basic run implementation that notifies the user
                print("[stub] Flask app would start here.")

        def abort(code: int, *args, **kwargs) -> None:
            raise Exception(f"Abort called with status {code}")

        # Global current_app proxy; exposes a ``config`` attribute used by the app
        current_app = SimpleNamespace(config={})

        def jsonify(obj: object) -> object:
            # In stubs, just return the object unchanged
            return obj

        def redirect(location: str, *args, **kwargs) -> str:
            return location

        def render_template(template_name: str, **context) -> str:
            # Return a simple string representation of the template call
            return f"[stub] render {template_name} {context}"

        def flash(message: str, category: str = "info") -> None:
            # In stub, simply print flash messages to stdout
            print(f"[flash:{category}] {message}")

        def has_request_context() -> bool:
            # Assume there is no real request context in stub
            return False

        # Simple session dictionary for storing user data across requests
        session: dict[str, object] = {}

        class Response:
            def __init__(self, response: object = None, status: int | None = None, **kwargs) -> None:
                self.response = response
                self.status_code = status or 200

            # Represent the response as a string when printed
            def __repr__(self) -> str:
                return f"<Response {self.status_code}>"

        class _Request:
            # Minimal request object exposing headers and remote_addr
            def __init__(self) -> None:
                self.headers: dict[str, str] = {}
                self.remote_addr: str | None = "127.0.0.1"

            def get_json(self) -> dict[str, object]:
                return {}

        request = _Request()

        def send_file(file, *args, **kwargs) -> object:
            # Simply return the file object/path in stub
            return file

        def url_for(endpoint: str, **values) -> str:
            # Construct a fake URL using the endpoint name
            prefix = values.get("_external", False) and "http://localhost" or ""
            return f"{prefix}/{endpoint}"

        class Blueprint:
            def __init__(self, name: str, import_name: str, url_prefix: str | None = None) -> None:
                self.name = name
                self.import_name = import_name
                self.url_prefix = url_prefix

            def route(self, *args, **kwargs):
                def decorator(func):
                    return func
                return decorator

            def register(self, *args, **kwargs) -> None:
                return None

        # Populate the flask module namespace
        flask_mod.Flask = Flask
        flask_mod.abort = abort
        flask_mod.current_app = current_app
        flask_mod.jsonify = jsonify
        flask_mod.redirect = redirect
        flask_mod.render_template = render_template
        flask_mod.flash = flash
        flask_mod.session = session
        flask_mod.Response = Response
        flask_mod.has_request_context = has_request_context
        flask_mod.request = request
        flask_mod.send_file = send_file
        flask_mod.url_for = url_for
        flask_mod.Blueprint = Blueprint

        register_module("flask", flask_mod)

    # ------------------------------------------------------------------
    # flask_login stubs
    # ------------------------------------------------------------------
    try:
        import flask_login  # type: ignore  # noqa: F401
    except Exception:
        login_mod = types.ModuleType("flask_login")

        class LoginManager:
            def __init__(self) -> None:
                self._callback = None
                self.login_view: str | None = None
                self.login_message: str | None = None
                self.login_message_category: str | None = None

            def init_app(self, app) -> None:
                # No‑op in stub
                return None

            def user_loader(self, func):  # type: ignore[override]
                # Register a callback to load users
                self._callback = func
                return func

        def login_required(func):
            # Decorator that returns the original function unchanged
            return func

        # Simple user proxy with minimal attributes used in the app
        current_user = SimpleNamespace(is_authenticated=False, role="", id=None)

        def login_user(user, remember: bool = False) -> None:
            # In stub, mark current_user as authenticated
            current_user.is_authenticated = True
            current_user.id = getattr(user, "id", None)
            current_user.role = getattr(user, "role", "")

        def logout_user() -> None:
            current_user.is_authenticated = False
            current_user.id = None
            current_user.role = ""

        class UserMixin:
            # Placeholder mixin for Flask‑Login
            def get_id(self):  # type: ignore[override]
                return str(getattr(self, "id", "0"))

        login_mod.LoginManager = LoginManager
        login_mod.login_required = login_required
        login_mod.current_user = current_user
        login_mod.login_user = login_user
        login_mod.logout_user = logout_user
        login_mod.UserMixin = UserMixin

        register_module("flask_login", login_mod)

    # ------------------------------------------------------------------
    # flask_sqlalchemy stubs
    # ------------------------------------------------------------------
    try:
        import flask_sqlalchemy  # type: ignore  # noqa: F401
    except Exception:
        sa_mod = types.ModuleType("flask_sqlalchemy")

        class _Query:
            """Minimal query object returning empty results for all operations."""

            def filter(self, *args, **kwargs) -> "_Query":
                return self

            def filter_by(self, **kwargs) -> "_Query":
                return self

            def order_by(self, *args, **kwargs) -> "_Query":
                return self

            def group_by(self, *args, **kwargs) -> "_Query":
                return self

            def join(self, *args, **kwargs) -> "_Query":
                return self

            def outerjoin(self, *args, **kwargs) -> "_Query":
                return self

            def options(self, *args, **kwargs) -> "_Query":
                return self

            def count(self) -> int:
                return 0

            def all(self) -> list[object]:
                return []

            def first(self) -> object | None:
                return None

            def get(self, _id) -> object | None:
                return None

            def get_or_404(self, _id) -> object:
                # Return None rather than raising
                return None

            def limit(self, *args, **kwargs) -> "_Query":
                return self

        class _Session:
            def add(self, obj: object) -> None:
                return None

            def commit(self) -> None:
                return None

            def query(self, model) -> _Query:
                return _Query()

        class _DB:
            """Lightweight stand‑in for SQLAlchemy database object."""

            Model = object

            # Column types used in model definitions; map all to object type
            class _ColumnType:
                def __init__(self, *args, **kwargs) -> None:
                    return None

            # SQL column type placeholders; each resolves to a callable type
            Integer = String = Date = DateTime = Boolean = LargeBinary = Text = JSON = _ColumnType

            Column = lambda *args, **kwargs: None  # type: ignore

            relationship = staticmethod(lambda *args, **kwargs: None)  # type: ignore

            # Foreign key definition placeholder
            ForeignKey = staticmethod(lambda *args, **kwargs: None)

            func = SimpleNamespace(count=lambda *args, **kwargs: 0)

            def __init__(self) -> None:
                self.session = _Session()

            def init_app(self, app) -> None:
                return None

            def create_all(self) -> None:
                return None

        def SQLAlchemy(app: object | None = None) -> _DB:
            # Always return the same DB instance irrespective of the app provided
            return _DB()

        sa_mod.SQLAlchemy = SQLAlchemy
        register_module("flask_sqlalchemy", sa_mod)

    # ------------------------------------------------------------------
    # flask_wtf and wtforms stubs
    # ------------------------------------------------------------------
    try:
        import flask_wtf  # type: ignore  # noqa: F401
    except Exception:
        wtf_mod = types.ModuleType("flask_wtf")

        class CSRFProtect:
            def __init__(self, *args, **kwargs) -> None:
                return None

            def init_app(self, app) -> None:
                return None

            def exempt(self, blueprint) -> None:
                return None

        wtf_mod.CSRFProtect = CSRFProtect

        class FlaskForm:
            """Minimal base form class used by WTForms.

            Real Flask‑WTF forms provide CSRF protection and validation
            helpers. This stub stores field definitions on the class and
            implements a trivial ``validate_on_submit`` method that always
            returns ``True``. Field instances do not retain any data in
            this stub; they serve only as placeholders so the rest of the
            application can access attributes on the form object.
            """

            def __init__(self, *args, **kwargs) -> None:
                # Copy default field values from class definitions to the instance
                for name, val in self.__class__.__dict__.items():
                    if isinstance(val, object) and not name.startswith("__"):
                        setattr(self, name, val)

            def validate_on_submit(self) -> bool:
                # Always assume form submission is valid in stub
                return True

        wtf_mod.FlaskForm = FlaskForm
        register_module("flask_wtf", wtf_mod)

    try:
        import wtforms  # type: ignore  # noqa: F401
    except Exception:
        wtforms_mod = types.ModuleType("wtforms")

        class _Field:
            def __init__(self, *args, **kwargs) -> None:
                return None

        # Map all common field types to the generic field class
        for _name in [
            "StringField",
            "PasswordField",
            "BooleanField",
            "DateField",
            "HiddenField",
            "SelectField",
            "SubmitField",
            "TextAreaField",
        ]:
            setattr(wtforms_mod, _name, _Field)

        # Create a nested validators submodule
        validators_mod = types.ModuleType("wtforms.validators")

        class _Validator:
            def __init__(self, *args, **kwargs) -> None:
                return None
            def __call__(self, form, field) -> None:
                return None

        # Map common validators to the generic validator
        for _name in [
            "DataRequired",
            "Email",
            "EqualTo",
            "Length",
            "Optional",
            "Regexp",
        ]:
            setattr(validators_mod, _name, _Validator)

        class ValidationError(Exception):
            pass

        validators_mod.ValidationError = ValidationError

        register_module("wtforms", wtforms_mod)
        register_module("wtforms.validators", validators_mod)

    # ------------------------------------------------------------------
    # SQLAlchemy stubs (non‑Flask)
    # ------------------------------------------------------------------
    try:
        import sqlalchemy  # type: ignore  # noqa: F401
    except Exception:
        sa2_mod = types.ModuleType("sqlalchemy")
        # Event stub with a ``listen`` function
        event_mod = types.ModuleType("sqlalchemy.event")
        def listen(*args, **kwargs) -> None:
            return None
        event_mod.listen = listen
        # func stub replicating SQL functions like count
        func_mod = types.ModuleType("sqlalchemy.func")
        func_mod.count = lambda *args, **kwargs: 0
        # orm submodule with validates decorator and joinedload function
        orm_mod = types.ModuleType("sqlalchemy.orm")
        def validates(*args, **kwargs):
            def decorator(func):
                return func
            return decorator
        def joinedload(*args, **kwargs):
            return None
        orm_mod.validates = validates
        orm_mod.joinedload = joinedload
        # Attach submodules
        sa2_mod.event = event_mod
        sa2_mod.func = func_mod
        sa2_mod.orm = orm_mod
        register_module("sqlalchemy", sa2_mod)
        register_module("sqlalchemy.event", event_mod)
        register_module("sqlalchemy.func", func_mod)
        register_module("sqlalchemy.orm", orm_mod)

    # ------------------------------------------------------------------
    # itsdangerous stubs
    # ------------------------------------------------------------------
    try:
        import itsdangerous  # type: ignore  # noqa: F401
    except Exception:
        itd_mod = types.ModuleType("itsdangerous")

        class BadSignature(Exception):
            pass

        class SignatureExpired(Exception):
            pass

        class URLSafeTimedSerializer:
            def __init__(self, secret: str) -> None:
                self.secret = secret

            def dumps(self, payload: dict[str, object]) -> str:
                # Serialize payload as a simple string representation
                return f"token:{payload}"  # not secure

            def loads(self, token: str, max_age: int | None = None) -> dict[str, object]:
                # Very naive implementation; simply strip the prefix and eval the dict
                try:
                    _, data = token.split(":", 1)
                    return eval(data)  # noqa: W0123
                except Exception:
                    raise BadSignature("Invalid token")

        itd_mod.BadSignature = BadSignature
        itd_mod.SignatureExpired = SignatureExpired
        itd_mod.URLSafeTimedSerializer = URLSafeTimedSerializer
        register_module("itsdangerous", itd_mod)

    # ------------------------------------------------------------------
    # werkzeug stubs
    # ------------------------------------------------------------------
    try:
        import werkzeug  # type: ignore  # noqa: F401
    except Exception:
        werk_mod = types.ModuleType("werkzeug")
        middleware_mod = types.ModuleType("werkzeug.middleware")
        proxy_fix_mod = types.ModuleType("werkzeug.middleware.proxy_fix")

        class ProxyFix:
            def __init__(self, app, *args, **kwargs) -> None:
                # Simply keep a reference to the original app
                self.app = app

            def __call__(self, environ, start_response):  # type: ignore[override]
                return self.app(environ, start_response)

        proxy_fix_mod.ProxyFix = ProxyFix
        middleware_mod.proxy_fix = proxy_fix_mod
        werk_mod.middleware = middleware_mod
        register_module("werkzeug", werk_mod)
        register_module("werkzeug.middleware", middleware_mod)
        register_module("werkzeug.middleware.proxy_fix", proxy_fix_mod)

    # ------------------------------------------------------------------
    # reportlab stubs
    # ------------------------------------------------------------------
    try:
        import reportlab  # type: ignore  # noqa: F401
    except Exception:
        rl_mod = types.ModuleType("reportlab")
        lib_mod = types.ModuleType("reportlab.lib")
        colors_mod = types.ModuleType("reportlab.lib.colors")
        # Define a few common colors used in Table styles
        colors_mod.grey = "grey"
        colors_mod.whitesmoke = "whitesmoke"
        colors_mod.beige = "beige"

        pagesizes_mod = types.ModuleType("reportlab.lib.pagesizes")
        pagesizes_mod.letter = "letter"

        platypus_mod = types.ModuleType("reportlab.platypus")

        class SimpleDocTemplate:
            def __init__(self, buffer, pagesize: object = None) -> None:
                self.buffer = buffer
                self.pagesize = pagesize

            def build(self, story: list[object]) -> None:
                # In stub, writing anything to the buffer is unnecessary
                return None

        class Table:
            def __init__(self, data: list[list[object]]) -> None:
                self.data = data

            def setStyle(self, style) -> None:
                return None

        class TableStyle:
            def __init__(self, styles: list[tuple]) -> None:
                self.styles = styles

        platypus_mod.SimpleDocTemplate = SimpleDocTemplate
        platypus_mod.Table = Table
        platypus_mod.TableStyle = TableStyle

        lib_mod.colors = colors_mod
        lib_mod.pagesizes = pagesizes_mod
        lib_mod.platypus = platypus_mod

        rl_mod.lib = lib_mod
        rl_mod.platypus = platypus_mod

        # Register all nested modules
        register_module("reportlab", rl_mod)
        register_module("reportlab.lib", lib_mod)
        register_module("reportlab.lib.colors", colors_mod)
        register_module("reportlab.lib.pagesizes", pagesizes_mod)
        register_module("reportlab.platypus", platypus_mod)

    # ------------------------------------------------------------------
    # cryptography stubs
    # ------------------------------------------------------------------
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore  # noqa: F401
    except Exception:
        crypto_mod = types.ModuleType("cryptography")
        haz_mod = types.ModuleType("cryptography.hazmat")
        primitives_mod = types.ModuleType("cryptography.hazmat.primitives")
        ciphers_mod = types.ModuleType("cryptography.hazmat.primitives.ciphers")
        aead_mod = types.ModuleType("cryptography.hazmat.primitives.ciphers.aead")

        class AESGCM:
            def __init__(self, key: bytes) -> None:
                self.key = key

            def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
                # Extremely naive encryption: simply return the plaintext
                return data

            def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
                # Simply return the data as plaintext
                return data

        aead_mod.AESGCM = AESGCM
        ciphers_mod.aead = aead_mod
        primitives_mod.ciphers = ciphers_mod
        haz_mod.primitives = primitives_mod
        crypto_mod.hazmat = haz_mod

        # Register nested modules
        register_module("cryptography", crypto_mod)
        register_module("cryptography.hazmat", haz_mod)
        register_module("cryptography.hazmat.primitives", primitives_mod)
        register_module("cryptography.hazmat.primitives.ciphers", ciphers_mod)
        register_module("cryptography.hazmat.primitives.ciphers.aead", aead_mod)

    # ------------------------------------------------------------------
    # pyotp stubs
    # ------------------------------------------------------------------
    try:
        import pyotp  # type: ignore  # noqa: F401
    except Exception:
        pyotp_mod = types.ModuleType("pyotp")

        class TOTP:
            def __init__(self, secret: str) -> None:
                self.secret = secret

            def verify(self, token: str, valid_window: int | None = None) -> bool:
                # Always return True for any token in stub
                return True

            def provisioning_uri(self, name: str, issuer_name: str | None = None) -> str:
                # Construct a dummy provisioning URI
                return f"otpauth://totp/{issuer_name or 'EnterpriseManager'}:{name}?secret={self.secret}"

        pyotp_mod.TOTP = TOTP
        register_module("pyotp", pyotp_mod)

    # ------------------------------------------------------------------
    # bcrypt stubs
    # ------------------------------------------------------------------
    try:
        import bcrypt  # type: ignore  # noqa: F401
    except Exception:
        bcrypt_mod = types.ModuleType("bcrypt")

        def gensalt(rounds: int = 12) -> bytes:
            return b"salt"

        def hashpw(password: bytes, salt: bytes) -> bytes:
            # Return a trivial hash: password concatenated with salt
            return password + salt

        def checkpw(password: bytes, hashed: bytes) -> bool:
            # Always succeed for demonstration; never use in production
            return True

        bcrypt_mod.gensalt = gensalt
        bcrypt_mod.hashpw = hashpw
        bcrypt_mod.checkpw = checkpw
        register_module("bcrypt", bcrypt_mod)

    # ------------------------------------------------------------------
    # python‑dotenv stubs
    # ------------------------------------------------------------------
    try:
        import dotenv  # type: ignore  # noqa: F401
    except Exception:
        dotenv_mod = types.ModuleType("dotenv")

        def load_dotenv(*args, **kwargs) -> None:
            # Loading environment variables is a no‑op in stub
            return None

        dotenv_mod.load_dotenv = load_dotenv
        register_module("dotenv", dotenv_mod)

