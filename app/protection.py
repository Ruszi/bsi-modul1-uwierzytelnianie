"""Moduł 2: ochrona przed botami i ruchem automatycznym.

Zawiera:
  * własną CAPTCHA – wariant 5: liczba narysowana znakami ASCII (ASCII art),
  * pole-pułapkę (honeypot) w formularzu logowania,
  * limit błędnych logowań na konto (blokada czasowa) i na adres IP,
  * rejestr prób logowania,
  * konto-pułapkę (Canarytoken) – jego użycie wysyła alert,
  * weryfikację Google reCAPTCHA po stronie serwera.
"""
import hmac
import random
import secrets
import threading
from datetime import timedelta

import pyfiglet
import requests
from flask import current_app, request

from .db import get_db, get_setting
from .utils import from_iso, now, to_iso

LOCKOUT_MINUTES = 15                     # wymaganie: blokada konta na 15 minut
HONEYPOT_FIELD = "website"               # nazwa ukrytego pola-pułapki


# ===================== CAPTCHA: ASCII ART (wariant 5) =====================

CAPTCHA_LENGTH = 5                       # liczba cyfr do przepisania
CAPTCHA_VALIDITY = timedelta(minutes=2)  # wyzwanie ważne 2 minuty
CAPTCHA_FONTS = ["standard", "big", "banner3", "doom"]   # losowa czcionka ASCII
NOISE_CHARS = "~^"                       # znaki "szumu" dosypywane w puste miejsca


def _render_ascii(text):
    """Rysuje cyfry znakami ASCII: każda cyfra osobno, losowa czcionka, losowy szum."""
    font = random.choice(CAPTCHA_FONTS)
    glyphs = [pyfiglet.figlet_format(ch, font=font).rstrip("\n").split("\n") for ch in text]
    height = max(len(g) for g in glyphs)
    rows = []
    for r in range(height):
        parts = []
        for g in glyphs:
            width = max(len(line) for line in g)
            line = g[r] if r < len(g) else ""
            parts.append(line.ljust(width))
        rows.append("  ".join(parts))
    # szum: ok. 8% pustych miejsc zamieniamy na losowy znak
    noisy = []
    for row in rows:
        noisy.append("".join(
            random.choice(NOISE_CHARS) if ch == " " and random.random() < 0.08 else ch
            for ch in row
        ))
    return "\n".join(noisy)


def new_captcha():
    """Tworzy nowe wyzwanie. Zwraca (id, rysunek ASCII). Odpowiedź zostaje TYLKO na serwerze."""
    db = get_db()
    db.execute("DELETE FROM captcha_challenges WHERE expires_at < ?", (to_iso(now()),))  # sprzątanie
    answer = "".join(secrets.choice("0123456789") for _ in range(CAPTCHA_LENGTH))
    challenge_id = secrets.token_urlsafe(16)
    db.execute(
        "INSERT INTO captcha_challenges (id, answer, expires_at) VALUES (?, ?, ?)",
        (challenge_id, answer, to_iso(now() + CAPTCHA_VALIDITY)),
    )
    db.commit()
    return challenge_id, _render_ascii(answer)


def check_captcha(challenge_id, user_answer):
    """Sprawdza odpowiedź. Wyzwanie jest usuwane OD RAZU (jednorazowe),
    niezależnie od tego, czy odpowiedź była dobra."""
    db = get_db()
    row = db.execute("SELECT * FROM captcha_challenges WHERE id = ?", (challenge_id or "",)).fetchone()
    if row is None:
        return False                                             # brak / już użyte
    db.execute("DELETE FROM captcha_challenges WHERE id = ?", (row["id"],))
    db.commit()
    if now() > from_iso(row["expires_at"]):
        return False                                             # wygasło
    answer = (user_answer or "").replace(" ", "").strip()
    return hmac.compare_digest(answer, row["answer"])


# ===================== HONEYPOT =====================

def honeypot_triggered():
    """Człowiek nie widzi pola 'website', więc go nie wypełni. Bot wypełnia wszystko."""
    return bool(request.form.get(HONEYPOT_FIELD, "").strip())


# ===================== REJESTR PRÓB I LIMIT IP =====================

def client_ip():
    """Adres IP klienta. Celowo NIE ufamy nagłówkowi X-Forwarded-For –
    bot mógłby go podrobić i obejść limit."""
    return request.remote_addr or "unknown"


def record_attempt(login, result):
    """Zapisuje próbę logowania. result: ok, bad_password, unknown_user, locked,
    captcha, honeypot, ip_limit, canary."""
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (ip, login, result, created_at) VALUES (?, ?, ?, ?)",
        (client_ip(), login[:64], result, to_iso(now())),
    )
    db.commit()


def ip_block_remaining():
    """Ile sekund blokady zostało dla tego IP (0 = brak blokady).
    Liczymy NIEUDANE próby z tego IP w oknie czasowym – niezależnie od loginu
    (ochrona przed password spraying)."""
    limit = get_setting("ip_max_failed", int)
    window = timedelta(minutes=get_setting("ip_window_minutes", int))
    since = to_iso(now() - window)
    rows = get_db().execute(
        "SELECT created_at FROM login_attempts WHERE ip = ? AND result != 'ok' AND created_at >= ? "
        "ORDER BY created_at",
        (client_ip(), since),
    ).fetchall()
    if len(rows) < limit:
        return 0
    # blokada trwa, dopóki najstarsza z ostatnich `limit` prób nie wypadnie z okna
    oldest_relevant = from_iso(rows[len(rows) - limit]["created_at"])
    return max(1, int((oldest_relevant + window - now()).total_seconds()))


# ===================== BLOKADA KONTA =====================

def account_lock_remaining(user):
    """Ile sekund blokady konta zostało (0 = konto nie jest zablokowane czasowo)."""
    until = from_iso(user["locked_until"])
    if until and until > now():
        return int((until - now()).total_seconds())
    return 0


def register_failed_login(user):
    """Zwiększa licznik błędów. Po przekroczeniu limitu blokuje konto na 15 min.
    Zwraca True, jeśli konto właśnie zostało zablokowane."""
    db = get_db()
    failed = user["failed_logins"] + 1
    if failed >= get_setting("max_failed_logins", int):
        db.execute("UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                   (to_iso(now() + timedelta(minutes=LOCKOUT_MINUTES)), user["id"]))
        db.commit()
        return True
    db.execute("UPDATE users SET failed_logins = ? WHERE id = ?", (failed, user["id"]))
    db.commit()
    return False


def reset_failed_logins(user_id):
    db = get_db()
    db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user_id,))
    db.commit()


# ===================== CANARYTOKEN: KONTO-PUŁAPKA =====================

def is_canary_login(login):
    canary = current_app.config.get("CANARY_LOGIN", "")
    return bool(canary) and login.lower() == canary.lower()


def trigger_canary(login):
    """Wywołuje adres Canarytokena -> Canarytokens wysyła alert e-mailem.
    Robimy to w osobnym wątku, żeby odpowiedź nie była wolniejsza (atakujący nie zauważy)."""
    url = current_app.config.get("CANARY_ACCOUNT_URL")
    if not url:
        current_app.logger.warning("Konto-pułapka użyte (%s), ale brak CANARY_ACCOUNT_URL", login)
        return
    params = {"login": login, "ip": client_ip()}

    def _hit():
        try:
            requests.get(url, params=params, timeout=5)
        except requests.RequestException:
            pass

    threading.Thread(target=_hit, daemon=True).start()


# ===================== GOOGLE reCAPTCHA =====================

RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def verify_recaptcha():
    """Weryfikuje token reCAPTCHA PO STRONIE SERWERA. Zwraca (ok, komunikat_błędu)."""
    token = request.form.get("g-recaptcha-response", "")
    if not token:                                     # brak tokenu -> od razu odrzucamy
        return False, "Potwierdź, że nie jesteś robotem (reCAPTCHA)."
    try:
        response = requests.post(
            RECAPTCHA_VERIFY_URL,
            data={"secret": current_app.config["RECAPTCHA_SECRET_KEY"],
                  "response": token,
                  "remoteip": client_ip()},
            timeout=5,
        )
        result = response.json()
    except (requests.RequestException, ValueError):
        return False, "Nie udało się zweryfikować reCAPTCHA. Spróbuj ponownie."
    if not result.get("success"):
        return False, "Weryfikacja reCAPTCHA nie powiodła się. Spróbuj ponownie."
    return True, None