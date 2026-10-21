"""Panel administratora: konta użytkowników i ustawienia bezpieczeństwa."""
import re

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from .auth import permission_required
from .db import get_db, get_setting, set_setting
from .security import MAX_LENGTH
from .users import create_user, issue_one_time_password, kill_sessions

bp = Blueprint("admin", __name__, url_prefix="/admin")

# Dozwolony login: 3–32 znaki, litery, cyfry, kropka, podkreślnik, myślnik
LOGIN_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")


def _roles():
    return get_db().execute("SELECT id, name, description FROM roles ORDER BY id").fetchall()


def _get_user(user_id):
    """Konto z nazwą roli albo 404."""
    user = get_db().execute(
        "SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
        (user_id,),
    ).fetchone()
    if user is None:
        abort(404)
    return user


def _protected(user, action):
    """Stałego konta ADMIN i własnego konta nie wolno blokować ani usuwać.
    Sprawdzamy to NA SERWERZE, a nie tylko przez ukrycie przycisku."""
    if user["is_system"]:
        flash(f"Nie można {action} stałego konta ADMIN.", "error")
        return True
    if user["id"] == g.user["id"]:
        flash(f"Nie można {action} własnego konta.", "error")
        return True
    return False


# ===================== LISTA KONT =====================

@bp.get("/users")
@permission_required("users.view")
def users():
    rows = get_db().execute(
        "SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON r.id = u.role_id "
        "ORDER BY u.is_system DESC, u.login"
    ).fetchall()
    return render_template("admin/users.html", users=rows)


# ===================== NOWE KONTO =====================

@bp.route("/users/new", methods=["GET", "POST"])
@permission_required("users.manage")
def user_new():
    errors, form = [], {"login": "", "full_name": "", "role_id": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        db = get_db()
        if not LOGIN_RE.match(form["login"]):
            errors.append("Login: 3–32 znaki, dozwolone litery, cyfry oraz . _ -")
        elif db.execute("SELECT 1 FROM users WHERE login = ?", (form["login"],)).fetchone():
            errors.append("Konto o takim loginie już istnieje.")
        if not form["full_name"]:
            errors.append("Podaj imię i nazwisko.")
        role = db.execute("SELECT name FROM roles WHERE id = ?", (form["role_id"] or 0,)).fetchone()
        if role is None:
            errors.append("Wybierz rolę.")
        if not errors:
            _, password, expires = create_user(db, form["login"], form["full_name"], role["name"])
            db.commit()
            # Hasło pokazujemy RAZ na stronie (nie przez flash – ciasteczko nie jest szyfrowane)
            return render_template("admin/one_time_password.html", login=form["login"],
                                   password=password, expires=expires, created=True)
    return render_template("admin/user_form.html", user=None, roles=_roles(), errors=errors, form=form)


# ===================== EDYCJA KONTA =====================

@bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@permission_required("users.manage")
def user_edit(user_id):
    user = _get_user(user_id)
    errors = []
    form = {"login": user["login"], "full_name": user["full_name"], "role_id": str(user["role_id"])}
    if request.method == "POST":
        form["full_name"] = request.form.get("full_name", "").strip()
        form["role_id"] = request.form.get("role_id", "")
        db = get_db()
        if not form["full_name"]:
            errors.append("Podaj imię i nazwisko.")
        role = db.execute("SELECT id FROM roles WHERE id = ?", (form["role_id"] or 0,)).fetchone()
        if role is None:
            errors.append("Wybierz rolę.")
        elif role["id"] != user["role_id"] and (user["is_system"] or user["id"] == g.user["id"]):
            errors.append("Nie można zmienić roli stałego konta ADMIN ani własnej roli.")
        if not errors:
            db.execute("UPDATE users SET full_name = ?, role_id = ? WHERE id = ?",
                       (form["full_name"], role["id"], user_id))
            if role["id"] != user["role_id"]:
                kill_sessions(db, user_id)          # nowe uprawnienia od następnego logowania
            db.commit()
            flash(f"Zapisano zmiany konta {user['login']}.", "success")
            return redirect(url_for("admin.users"))
    return render_template("admin/user_form.html", user=user, roles=_roles(), errors=errors, form=form)


# ===================== BLOKADA / ODBLOKOWANIE / USUNIĘCIE =====================

@bp.post("/users/<int:user_id>/block")
@permission_required("users.manage")
def user_block(user_id):
    user = _get_user(user_id)
    if not _protected(user, "zablokować"):
        db = get_db()
        db.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
        kill_sessions(db, user_id)                  # wyloguj go od razu
        db.commit()
        flash(f"Zablokowano konto {user['login']}.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/unblock")
@permission_required("users.manage")
def user_unblock(user_id):
    user = _get_user(user_id)
    db = get_db()
    db.execute("UPDATE users SET is_blocked = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash(f"Odblokowano konto {user['login']}.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/delete")
@permission_required("users.manage")
def user_delete(user_id):
    user = _get_user(user_id)
    if not _protected(user, "usunąć"):
        db = get_db()
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))   # sesje i historia znikną (CASCADE)
        db.commit()
        flash(f"Usunięto konto {user['login']}.", "success")
    return redirect(url_for("admin.users"))


# ===================== RESET HASŁA I 2FA =====================

@bp.post("/users/<int:user_id>/reset-password")
@permission_required("users.manage")
def user_reset_password(user_id):
    user = _get_user(user_id)
    if user["id"] == g.user["id"]:
        flash("Własne hasło zmień przez „Zmień hasło”.", "error")
        return redirect(url_for("admin.users"))
    db = get_db()
    password, expires = issue_one_time_password(db, user_id)   # nowe hasło + wylogowanie
    db.commit()
    return render_template("admin/one_time_password.html", login=user["login"],
                           password=password, expires=expires, created=False)


@bp.post("/users/<int:user_id>/reset-2fa")
@permission_required("users.manage")
def user_reset_2fa(user_id):
    """Wyłącza 2FA, np. gdy użytkownik zgubił telefon (przyda się w etapie 9)."""
    user = _get_user(user_id)
    db = get_db()
    db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
               (user_id,))
    db.commit()
    flash(f"Wyłączono 2FA dla konta {user['login']}.", "success")
    return redirect(url_for("admin.users"))


# ===================== USTAWIENIA =====================

@bp.route("/settings", methods=["GET", "POST"])
@permission_required("settings.manage")
def settings():
    errors = []
    if request.method == "POST":
        # pole: (minimum, maksimum, etykieta do komunikatu)
        limits = {
            "min_length": (8, MAX_LENGTH, "Minimalna długość hasła"),
            "password_max_age_days": (0, 3650, "Ważność hasła"),
            "session_idle_minutes": (1, 240, "Czas bezczynności sesji"),
        }
        values = {}
        for key, (low, high, label) in limits.items():
            try:
                value = int(request.form.get(key, ""))
            except ValueError:
                value = None
            if value is None or not low <= value <= high:
                errors.append(f"{label}: podaj liczbę całkowitą z zakresu {low}–{high}.")
            values[key] = value
        if not errors:
            for key, value in values.items():
                set_setting(key, value)
            set_setting("hibp_enabled", request.form.get("hibp_enabled") == "on")   # checkbox
            get_db().commit()
            flash("Zapisano ustawienia bezpieczeństwa.", "success")
            return redirect(url_for("admin.settings"))

    current = {
        "min_length": get_setting("min_length", int),
        "hibp_enabled": get_setting("hibp_enabled", bool),
        "password_max_age_days": get_setting("password_max_age_days", int),
        "session_idle_minutes": get_setting("session_idle_minutes", int),
    }
    return render_template("admin/settings.html", s=current, errors=errors)