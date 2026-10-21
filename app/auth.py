"""Identyfikacja, uwierzytelnianie, sesje i kontrola uprawnień."""
import functools
import hashlib
import secrets
from datetime import timedelta

from flask import (Blueprint, abort, current_app, flash, g, redirect, render_template,
                   request, url_for)

from .db import get_db, get_setting
from .security import DUMMY_HASH, hash_password, needs_rehash, verify_password, verify_totp
from .utils import from_iso, now, to_iso

bp = Blueprint("auth", __name__)

SESSION_COOKIE = "sid"                              # nazwa ciasteczka z tokenem sesji
GENERIC_LOGIN_ERROR = "Login lub hasło niepoprawne"
MAX_MFA_ATTEMPTS = 5                                # limit błędnych kodów 2FA

# Strony dostępne, gdy użytkownik MUSI zmienić hasło (wszystko inne jest zablokowane)
FORCED_CHANGE_ALLOWED = {"static", "auth.login", "auth.logout", "auth.login_totp", "account.required_change"}


# ===================== SESJE =====================

def hash_token(token):
    """Skrót tokenu do zapisania w bazie. Sam token jest tylko w ciasteczku,
    więc wyciek bazy nie pozwala przejąć cudzej sesji."""
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id, stage="full"):
    """Tworzy NOWĄ sesję po zalogowaniu (nowy token = ochrona przed session fixation)."""
    token = secrets.token_urlsafe(32)               # 256 bitów losowości
    timestamp = to_iso(now())
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, stage, created_at, last_activity) "
        "VALUES (?, ?, ?, ?, ?)",
        (hash_token(token), user_id, stage, timestamp, timestamp),
    )
    db.commit()
    g.new_session_token = token                     # after_request ustawi ciasteczko


def end_current_session():
    """Wylogowanie: usuwa sesję z BAZY (nie tylko ciasteczko)."""
    row = g.get("session_row")
    if row is not None:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        db.commit()
    g.session_row = None
    g.clear_cookie = True


@bp.before_app_request
def load_session():
    """PRZED każdym żądaniem: kto jest zalogowany i co mu wolno?"""
    g.user = None
    g.pending_user = None                           # zalogowany hasłem, czeka na kod 2FA
    g.session_row = None
    g.session_expired = False
    g.permissions = frozenset()                     # zbiór uprawnień – na start pusty
    if request.endpoint == "static":
        return

    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return

    db = get_db()
    row = db.execute("SELECT * FROM sessions WHERE token_hash = ?", (hash_token(token),)).fetchone()
    if row is None:
        g.clear_cookie = True
        return

    # --- wygaśnięcie po bezczynności ---
    idle_minutes = get_setting("session_idle_minutes", int)
    if now() - from_iso(row["last_activity"]) > timedelta(minutes=idle_minutes):
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        db.commit()
        g.clear_cookie = True
        g.session_expired = True
        return

    # --- konto zablokowane lub usunięte w trakcie sesji ---
    user = db.execute(
        "SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?",
        (row["user_id"],),
    ).fetchone()
    if user is None or user["is_blocked"]:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        db.commit()
        g.clear_cookie = True
        return

    # --- sesja ważna: odśwież czas aktywności ---
    db.execute("UPDATE sessions SET last_activity = ? WHERE token_hash = ?",
               (to_iso(now()), row["token_hash"]))
    db.commit()
    g.session_row = row
    if row["stage"] == "full":                      # pełne zalogowanie
        g.user = user
        g.idle_seconds = idle_minutes * 60
        # Uprawnienia ROLI użytkownika (RBAC: użytkownik -> rola -> uprawnienia)
        g.permissions = frozenset(
            r["code"] for r in db.execute(
                "SELECT p.code FROM permissions p "
                "JOIN role_permissions rp ON rp.permission_id = p.id "
                "WHERE rp.role_id = ?",
                (user["role_id"],),
            )
        )
    else:                                           # stage == 'mfa': hasło OK, brak kodu
        g.pending_user = user                       # NIE ustawiamy g.user -> brak dostępu

# ===================== WYMUSZONA ZMIANA HASŁA =====================

def password_change_reason(user):
    """'first' – hasło jednorazowe/nadane przez admina,
    'expired' – minęła ważność hasła, None – nie musi zmieniać."""
    if user["must_change_password"]:
        return "first"
    max_age = get_setting("password_max_age_days", int)
    changed = from_iso(user["password_changed_at"])
    if max_age > 0 and changed and now() > changed + timedelta(days=max_age):
        return "expired"
    return None


@bp.before_app_request
def enforce_password_change():
    """Po load_session: kto musi zmienić hasło, trafia na stronę zmiany."""
    if (g.user is not None and password_change_reason(g.user)
            and request.endpoint not in FORCED_CHANGE_ALLOWED):
        return redirect(url_for("account.required_change"))


def current_session_hash():
    """Skrót tokenu bieżącej sesji (żeby po zmianie hasła jej nie zamknąć)."""
    if g.get("new_session_token"):
        return hash_token(g.new_session_token)
    row = g.get("session_row")
    return row["token_hash"] if row else None


# ===================== CIASTECZKO =====================

@bp.after_app_request
def apply_session_cookie(response):
    """PO każdym żądaniu: ustaw lub skasuj ciasteczko sesji."""
    if g.get("new_session_token"):
        response.set_cookie(
            SESSION_COOKIE, g.new_session_token,
            httponly=True,                          # JavaScript nie odczyta ciasteczka
            samesite="Lax",                         # nie wysyłaj z obcych stron
            secure=current_app.config.get("AUTH_COOKIE_SECURE", False),
            path="/",
        )
    elif g.get("clear_cookie"):
        response.delete_cookie(SESSION_COOKIE, path="/")
    if g.get("user") is not None:
        response.headers["Cache-Control"] = "no-store"   # "Wstecz" nie pokaże stron po wylogowaniu
    return response


# ===================== DEKORATORY AUTORYZACJI =====================

def _to_login():
    if g.get("session_expired"):
        flash("Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.", "info")
    return redirect(url_for("auth.login"))


def login_required(view):
    """Strona tylko dla zalogowanych."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return _to_login()
        return view(*args, **kwargs)
    return wrapped


def permission_required(*codes):
    """Strona tylko dla ról z podanymi uprawnieniami (sprawdzane NA SERWERZE)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return _to_login()
            if not set(codes) <= g.permissions:     # brakuje choć jednego uprawnienia
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ===================== WIDOKI =====================

@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("main.index"))
    if request.args.get("timeout") or g.session_expired:
        flash("Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.", "info")

    if request.method == "GET":
        return render_template("login.html", login="")

    login_value = request.form.get("login", "").strip()
    password = request.form.get("password", "")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE login = ?", (login_value,)).fetchone()

    # --- 1. Hasło (stały czas dzięki DUMMY_HASH) ---
    if user is None:
        verify_password(DUMMY_HASH, password)
        password_ok = False
    else:
        password_ok = verify_password(user["password_hash"], password)

    if not password_ok:
        flash(GENERIC_LOGIN_ERROR, "error")
        return render_template("login.html", login=login_value)

    # --- 2. Sprawdzenia po poprawnym haśle ---
    if user["is_blocked"]:
        flash("Konto jest zablokowane. Skontaktuj się z administratorem.", "error")
        return render_template("login.html", login=login_value)

    expires = from_iso(user["one_time_expires_at"])
    if expires and now() > expires:
        flash("Hasło jednorazowe wygasło. Poproś administratora o nowe.", "error")
        return render_template("login.html", login=login_value)

    if needs_rehash(user["password_hash"]):
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (hash_password(password), user["id"]))
        db.commit()

    # --- 3. Sukces hasła ---
    end_current_session()
    if user["totp_enabled"]:                        # 2FA włączone -> najpierw kod
        start_session(user["id"], "mfa")
        return redirect(url_for("auth.login_totp"))
    start_session(user["id"], "full")               # bez 2FA -> od razu pulpit
    return redirect(url_for("main.index"))


@bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    """Drugi krok logowania: kod z aplikacji na telefonie."""
    user = g.pending_user
    if user is None:                                # brak sesji 'mfa' -> od początku
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        db = get_db()
        step = verify_totp(user["totp_secret"], request.form.get("code", ""), user["totp_last_step"])
        if step is None:                            # zły kod
            attempts = g.session_row["mfa_attempts"] + 1
            if attempts >= MAX_MFA_ATTEMPTS:        # limit prób -> koniec sesji
                end_current_session()
                flash("Zbyt wiele błędnych kodów. Zaloguj się ponownie.", "error")
                return redirect(url_for("auth.login"))
            db.execute("UPDATE sessions SET mfa_attempts = ? WHERE token_hash = ?",
                       (attempts, g.session_row["token_hash"]))
            db.commit()
            flash("Niepoprawny kod weryfikacyjny.", "error")
        else:                                       # dobry kod
            db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
            db.commit()
            end_current_session()                   # sesja 'mfa' -> usunięta
            start_session(user["id"], "full")       # NOWY token dla pełnej sesji
            return redirect(url_for("main.index"))

    return render_template("login_totp.html")


@bp.post("/logout")                                 # tylko POST z tokenem CSRF
def logout():
    end_current_session()
    flash("Wylogowano.", "info")
    return redirect(url_for("auth.login"))