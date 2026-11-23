"""Konto zalogowanego użytkownika: zmiana hasła i weryfikacja dwuetapowa."""
import segno
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from .auth import current_session_hash, login_required, password_change_reason
from .db import get_db, get_setting
from .security import (check_password_policy, new_totp_secret, totp_uri,
                       verify_password, verify_totp)
from .users import previous_hashes, set_password
from .protection import verify_recaptcha
from .audit import FAILURE, log_event        # MODUŁ 3: dziennik zdarzeń
import re

bp = Blueprint("account", __name__, url_prefix="/account")


def _policy():
    """Aktualne ustawienia polityki – do wyświetlenia podpowiedzi w formularzu."""
    return {"min_length": get_setting("min_length", int),
            "hibp": get_setting("hibp_enabled", bool)}


def _log_reasons(errors):
    """MODUŁ 3: powody odrzucenia do dziennika – bez długości hasła (to też informacja o haśle)."""
    return "; ".join(re.sub(r" \(obecnie: \d+\)", "", e) for e in errors)

def _validate_new_password(user, new_password, repeated):
    """Wspólne sprawdzenie nowego hasła dla obu formularzy."""
    errors = []
    if new_password != repeated:
        errors.append("Podane nowe hasła nie są identyczne.")
    errors += check_password_policy(
        new_password,
        min_length=get_setting("min_length", int),
        hibp_enabled=get_setting("hibp_enabled", bool),
        previous_hashes=previous_hashes(get_db(), user),
    )
    return errors


@bp.route("/required", methods=["GET", "POST"])
@login_required
def required_change():
    """WYMUSZONA zmiana hasła (pierwsze logowanie lub wygasłe hasło)."""
    reason = password_change_reason(g.user)
    if reason is None:                               # nie musi zmieniać -> na pulpit
        return redirect(url_for("main.index"))

    errors = []
    if request.method == "POST":
        ok, captcha_error = verify_recaptcha()       # MODUŁ 2: najpierw reCAPTCHA
        if not ok:
            errors = [captcha_error]
        else:
            errors = _validate_new_password(g.user, request.form.get("new_password", ""),
                                            request.form.get("new_password2", ""))
        if not errors:
            db = get_db()
            set_password(db, g.user["id"], request.form["new_password"],
                         keep_session_hash=current_session_hash())
            db.commit()
            log_event("PASSWORD_CHANGE", "Wymuszona zmiana hasła zakończona")
            flash("Hasło zostało ustawione.", "success")
            return redirect(url_for("main.index"))
        else:
            # zapisujemy POWÓD odrzucenia, nigdy samo hasło
            log_event("PASSWORD_CHANGE", "Nieudana wymuszona zmiana hasła: " + _log_reasons(errors), FAILURE)
    return render_template("account/required.html", reason=reason, errors=errors, policy=_policy())
    return render_template("account/required.html", reason=reason, errors=errors, policy=_policy())


@bp.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    """ZWYKŁA zmiana hasła: wymaga podania obecnego hasła."""
    errors = []
    if request.method == "POST":
        ok, captcha_error = verify_recaptcha()       # MODUŁ 2: najpierw reCAPTCHA
        if not ok:
            errors.append(captcha_error)
        elif not verify_password(g.user["password_hash"], request.form.get("old_password", "")):
            errors.append("Aktualne hasło jest niepoprawne.")
        else:
            errors = _validate_new_password(g.user, request.form.get("new_password", ""),
                                            request.form.get("new_password2", ""))
        if not errors:
            db = get_db()
            set_password(db, g.user["id"], request.form["new_password"],
                         keep_session_hash=current_session_hash())
            db.commit()
            log_event("PASSWORD_CHANGE", "Zmiana hasła – pozostałe sesje zakończone")
            flash("Hasło zostało zmienione. Pozostałe sesje tego konta zostały zakończone.", "success")
            return redirect(url_for("main.index"))
        else:
            log_event("PASSWORD_CHANGE", "Nieudana zmiana hasła: " + _log_reasons(errors), FAILURE)
    return render_template("account/password.html", errors=errors, policy=_policy())

# ===================== WERYFIKACJA DWUETAPOWA (TOTP) =====================

@bp.get("/2fa")
@login_required
def twofa():
    """Strona 2FA. W trakcie konfiguracji pokazuje kod QR."""
    qr = None
    if g.user["totp_secret"] and not g.user["totp_enabled"]:
        # kod QR jako obrazek SVG wstawiony bezpośrednio w stronę
        qr = segno.make(totp_uri(g.user["totp_secret"], g.user["login"]), error="m").svg_data_uri(scale=5, border=2)
    return render_template("account/twofa.html", qr=qr)


@bp.post("/2fa/start")
@login_required
def twofa_start():
    """Krok 1: losujemy sekret (2FA jeszcze NIEaktywne)."""
    if not g.user["totp_enabled"]:
        db = get_db()
        db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
                   (new_totp_secret(), g.user["id"]))
        db.commit()
    return redirect(url_for("account.twofa"))


@bp.post("/2fa/confirm")
@login_required
def twofa_confirm():
    """Krok 2: użytkownik wpisuje kod z telefonu – dopiero wtedy włączamy 2FA.
    To potwierdza, że telefon jest poprawnie skonfigurowany."""
    if not g.user["totp_secret"] or g.user["totp_enabled"]:
        return redirect(url_for("account.twofa"))
    step = verify_totp(g.user["totp_secret"], request.form.get("code", ""), None)
    if step is None:
        flash("Kod nie pasuje. Sprawdź, czy czas w telefonie jest ustawiony automatycznie.", "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?", (step, g.user["id"]))
        db.commit()
        log_event("MFA_CHANGE", "Włączono weryfikację dwuetapową (TOTP)")
        flash("Weryfikacja dwuetapowa została włączona.", "success")
    return redirect(url_for("account.twofa"))


@bp.post("/2fa/cancel")
@login_required
def twofa_cancel():
    """Rezygnacja w trakcie konfiguracji."""
    if not g.user["totp_enabled"]:
        db = get_db()
        db.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (g.user["id"],))
        db.commit()
    return redirect(url_for("account.twofa"))


@bp.post("/2fa/disable")
@login_required
def twofa_disable():
    """Wyłączenie 2FA wymaga hasła ORAZ aktualnego kodu."""
    password_ok = verify_password(g.user["password_hash"], request.form.get("password", ""))
    step = None
    if g.user["totp_enabled"]:
        step = verify_totp(g.user["totp_secret"], request.form.get("code", ""), g.user["totp_last_step"])
    if not password_ok or step is None:
        log_event("MFA_CHANGE", "Nieudana próba wyłączenia 2FA (złe hasło lub kod)", FAILURE)
        flash("Niepoprawne hasło lub kod weryfikacyjny.", "error")
    else:
        db = get_db()
        db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
                   (g.user["id"],))
        db.commit()
        log_event("MFA_CHANGE", "Wyłączono weryfikację dwuetapową")
        flash("Weryfikacja dwuetapowa została wyłączona.", "info")
    return redirect(url_for("account.twofa"))