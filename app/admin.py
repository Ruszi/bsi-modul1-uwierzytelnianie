"""Panel administratora: konta użytkowników i ustawienia bezpieczeństwa."""
import json
import re

from flask import (Blueprint, Response, abort, flash, g, redirect, render_template, request,
                   url_for)
from .auth import permission_required
from .db import get_db, get_setting, set_setting
from .security import MAX_LENGTH
from .users import create_user, issue_one_time_password, kill_sessions
from .utils import now, to_iso
from .audit import (EVENT_TYPES, FAILURE, filter_entries, log_event, read_alerts,   # MODUŁ 3
                    read_entries, verify_integrity)

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


_ACTION_TYPES = {"zablokować": "USER_BLOCK", "usunąć": "USER_DELETE"}   # MODUŁ 3: typ wpisu w dzienniku


def _protected(user, action):
    """Stałego konta ADMIN i własnego konta nie wolno blokować ani usuwać.
    Sprawdzamy to NA SERWERZE, a nie tylko przez ukrycie przycisku."""
    if user["is_system"]:
        flash(f"Nie można {action} stałego konta ADMIN.", "error")
        log_event(_ACTION_TYPES[action], f"Próba: {action} stałe konto ADMIN – odrzucona", FAILURE)
        return True
    if user["id"] == g.user["id"]:
        flash(f"Nie można {action} własnego konta.", "error")
        log_event(_ACTION_TYPES[action], f"Próba: {action} własne konto – odrzucona", FAILURE)
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
    return render_template("admin/users.html", users=rows, now_iso=to_iso(now()))


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
            log_event("USER_CREATE", f"Utworzono konto {form['login']} z rolą {role['name']}")
            # Hasło pokazujemy RAZ na stronie (nie przez flash – ciasteczko nie jest szyfrowane)
            return render_template("admin/one_time_password.html", login=form["login"],
                                   password=password, expires=expires, created=True)
        if errors:
          log_event("USER_CREATE", f"Nieudane utworzenie konta {form['login']}: " + "; ".join(errors), FAILURE)
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
        role = db.execute("SELECT id, name FROM roles WHERE id = ?", (form["role_id"] or 0,)).fetchone()
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
            if role["id"] != user["role_id"]:
              log_event("ROLE_CHANGE", f"Konto {user['login']}: rola {user['role_name']} -> {role['name']}")
            if form["full_name"] != user["full_name"]:
              log_event("USER_UPDATE", f"Konto {user['login']}: zmieniono imię i nazwisko")
            flash(f"Zapisano zmiany konta {user['login']}.", "success")
            return redirect(url_for("admin.users"))
        if errors:
          log_event("USER_UPDATE", f"Nieudana edycja konta {user['login']}: " + "; ".join(errors), FAILURE)
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
        log_event("USER_BLOCK", f"Zablokowano konto {user['login']}")
        flash(f"Zablokowano konto {user['login']}.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/unblock")
@permission_required("users.manage")
def user_unblock(user_id):
    user = _get_user(user_id)
    db = get_db()
        # odblokowanie zdejmuje też blokadę czasową po błędnych logowaniach (MODUŁ 2)
    db.execute("UPDATE users SET is_blocked = 0, failed_logins = 0, locked_until = NULL WHERE id = ?",
               (user_id,))
    db.commit()
    log_event("USER_UNBLOCK", f"Odblokowano konto {user['login']}")
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
        log_event("USER_DELETE", f"Usunięto konto {user['login']}")
        flash(f"Usunięto konto {user['login']}.", "success")
    return redirect(url_for("admin.users"))


# ===================== RESET HASŁA I 2FA =====================

@bp.post("/users/<int:user_id>/reset-password")
@permission_required("users.manage")
def user_reset_password(user_id):
    user = _get_user(user_id)
    if user["id"] == g.user["id"]:
        flash("Własne hasło zmień przez „Zmień hasło”.", "error")
        log_event("PASSWORD_RESET", "Próba resetu własnego hasła – odrzucona", FAILURE)
        return redirect(url_for("admin.users"))
    db = get_db()
    password, expires = issue_one_time_password(db, user_id)   # nowe hasło + wylogowanie
    db.commit()
    log_event("PASSWORD_RESET", f"Nadano nowe hasło jednorazowe kontu {user['login']}")   # hasła NIE zapisujemy
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
    log_event("MFA_CHANGE", f"Administrator wyłączył 2FA kontu {user['login']}")
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
            # MODUŁ 2
            "max_failed_logins": (1, 20, "Limit błędnych logowań na konto"),
            "ip_max_failed": (3, 1000, "Limit nieudanych prób z jednego IP"),
            "ip_window_minutes": (1, 1440, "Okno czasowe limitu IP"),
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
            # MODUŁ 3: zapamiętujemy, co dokładnie się zmieniło (stara -> nowa wartość)
            new_hibp = request.form.get("hibp_enabled") == "on"
            changes = [f"{key}: {get_setting(key, int)} -> {value}"
                       for key, value in values.items() if get_setting(key, int) != value]
            if get_setting("hibp_enabled", bool) != new_hibp:
                changes.append(f"hibp_enabled: {int(not new_hibp)} -> {int(new_hibp)}")
            for key, value in values.items():
                set_setting(key, value)
            set_setting("hibp_enabled", new_hibp)   # checkbox
            get_db().commit()
            log_event("SETTINGS_CHANGE", "Zmieniono: " + (", ".join(changes) or "bez zmian wartości"))
            flash("Zapisano ustawienia bezpieczeństwa.", "success")
            return redirect(url_for("admin.settings"))
        log_event("SETTINGS_CHANGE", "Odrzucono zmianę ustawień: " + "; ".join(errors), FAILURE)

    current = {
        "min_length": get_setting("min_length", int),
        "hibp_enabled": get_setting("hibp_enabled", bool),
        "password_max_age_days": get_setting("password_max_age_days", int),
        "session_idle_minutes": get_setting("session_idle_minutes", int),
        "max_failed_logins": get_setting("max_failed_logins", int),
        "ip_max_failed": get_setting("ip_max_failed", int),
        "ip_window_minutes": get_setting("ip_window_minutes", int),
    }
    return render_template("admin/settings.html", s=current, errors=errors)


# ===================== MODUŁ 2: REJESTR PRÓB LOGOWANIA =====================

@bp.get("/attempts")
@permission_required("users.view")
def attempts():
    """Ostatnie 200 prób logowania – widać, które zabezpieczenie zadziałało."""
    db = get_db()
    rows = db.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 200").fetchall()
    summary = db.execute(
        "SELECT result, COUNT(*) AS n FROM login_attempts GROUP BY result ORDER BY n DESC"
    ).fetchall()
    return render_template("admin/attempts.html", rows=rows, summary=summary)



# ===================== MODUŁ 3: DZIENNIK ZDARZEŃ =====================
# Celowo NIE ma tu żadnej trasy do edycji ani usuwania wpisów
# i żadnego ustawienia, które wyłączałoby rejestrowanie zdarzeń.

def _log_filters():
    """Filtry z adresu strony, np. /admin/logs?user=jkowalski&action=LOGIN_FAILED"""
    return {k: request.args.get(k, "").strip() for k in ("user", "action", "date_from", "date_to")}


def _describe(filters):
    used = [f"{k}={v}" for k, v in filters.items() if v]
    return ", ".join(used) if used else "bez filtrów"


@bp.get("/logs")
@permission_required("logs.view")
def logs():
    filters = _log_filters()
    rows = filter_entries(read_entries(), **filters)
    log_event("LOG_VIEW", f"Podgląd dziennika ({_describe(filters)}), wyników: {len(rows)}")
    return render_template("admin/logs.html", rows=list(reversed(rows))[:500], total=len(rows),
                           f=filters, types=EVENT_TYPES)


@bp.get("/logs/export")
@permission_required("logs.view")
def logs_export():
    """Eksport wpisów (z tymi samymi filtrami) do pliku JSON."""
    filters = _log_filters()
    rows = filter_entries(read_entries(), **filters)
    log_event("LOG_EXPORT", f"Eksport dziennika do pliku JSON ({_describe(filters)}), wpisów: {len(rows)}")
    body = json.dumps({"exported_at": to_iso(now()), "exported_by": g.user["login"],
                       "filters": filters, "entries": rows}, ensure_ascii=False, indent=2)
    filename = f"dziennik_{now():%Y%m%d_%H%M%S}.json"
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@bp.route("/logs/verify", methods=["GET", "POST"])
@permission_required("logs.verify")
def logs_verify():
    """Weryfikacja integralności – uruchamia ją administrator przyciskiem (POST)."""
    result = None
    if request.method == "POST":
        result = verify_integrity()
        # wynik weryfikacji też trafia do dziennika (już PO sprawdzeniu)
        log_event("LOG_VERIFY", result["message"], "sukces" if result["ok"] else FAILURE)
    return render_template("admin/logs_verify.html", result=result)


@bp.get("/alerts")
@permission_required("logs.view")
def alerts():
    """Podgląd pliku alertów (kanał z wariantu 5)."""
    return render_template("admin/alerts.html", alerts=list(reversed(read_alerts())))