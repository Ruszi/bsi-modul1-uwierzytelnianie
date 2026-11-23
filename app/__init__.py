import os
import secrets
from pathlib import Path

from flask import Flask, g, render_template, request
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()   # ochrona formularzy przed atakiem CSRF


def _secret_key(instance_path):
    """Losowy klucz do podpisywania ciasteczek, zapisany w instance/ (poza repozytorium)."""
    key_file = Path(instance_path) / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
    return key_file.read_text().strip()


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config["DATABASE"] = os.path.join(app.instance_path, "app.sqlite")
    app.config["SECRET_KEY"] = _secret_key(app.instance_path)

    # ===== MODUŁ 2: klucze i adresy z pliku instance/config.py (poza repozytorium!) =====
    # Wartości domyślne reCAPTCHA to publiczne KLUCZE TESTOWE Google (zawsze akceptują token).
    app.config["RECAPTCHA_SITE_KEY"] = "6LeIxAcTAAAAAJcZVRqyHh71UMIYGNQ_MXjiZKhI"
    app.config["RECAPTCHA_SECRET_KEY"] = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
    app.config["CANARY_LOGIN"] = "backup_admin"         # login konta-pułapki
    app.config["CANARY_ACCOUNT_URL"] = None              # adres Canarytokena (Web bug)
    app.config.from_pyfile("config.py", silent=True)     # nadpisuje powyższe, jeśli plik istnieje

    from . import db
    db.init_app(app)                     # zamykanie bazy + komendy init-db i reset-password
    csrf.init_app(app)                   # każdy formularz POST musi mieć poprawny csrf_token

    # ===== Podłączenie części aplikacji (blueprintów) =====
    from . import auth
    app.register_blueprint(auth.bp)      # /login, /logout
    from . import main
    app.register_blueprint(main.bp)      # pulpit pod adresem /
    from . import account
    app.register_blueprint(account.bp)   # /account/required, /account/password
    from . import docs
    app.register_blueprint(docs.bp)      # /docs/...
    from . import admin
    app.register_blueprint(admin.bp)     # /admin/users, /admin/settings

    # ===== Własne strony błędów =====
    @app.errorhandler(403)
    def forbidden(_e):
                # MODUŁ 3: każda odmowa dostępu trafia do dziennika (reguła: >=3 w 10 min -> alert)
        from .audit import FAILURE, log_event
        log_event("ACCESS_DENIED", f"Brak uprawnień: {request.method} {request.path}", FAILURE)
        return render_template("error.html", code=403, title="Brak uprawnień",
                               message="Twoja rola nie ma uprawnień do tego zasobu."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, title="Nie znaleziono",
                               message="Taka strona nie istnieje."), 404

    # ===== Zmienne dostępne w każdym szablonie =====
    @app.context_processor
    def inject_can():
        def can(code):
            return code in g.get("permissions", frozenset())
        return {"can": can, "recaptcha_site_key": app.config["RECAPTCHA_SITE_KEY"]}

    return app