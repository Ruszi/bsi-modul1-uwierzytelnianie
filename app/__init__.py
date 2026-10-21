import os
import secrets
from pathlib import Path

from flask import Flask, g, render_template
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
        return render_template("error.html", code=403, title="Brak uprawnień",
                               message="Twoja rola nie ma uprawnień do tego zasobu."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, title="Nie znaleziono",
                               message="Taka strona nie istnieje."), 404

    # ===== Funkcja can('kod') dostępna w każdym szablonie =====
    @app.context_processor
    def inject_can():
        def can(code):
            return code in g.get("permissions", frozenset())
        return {"can": can}

    return app