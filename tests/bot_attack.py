"""Skrypt symulujący bota atakującego logowanie WŁASNEJ aplikacji (moduł 2).

UWAGA: uruchamiać wyłącznie na własnej aplikacji na localhost.
Atak na cudzy system bez zgody właściciela może być przestępstwem.

Uruchomienie (aplikacja musi działać w drugim terminalu):
    python tests/bot_attack.py
"""
import html
import re
import sys
from urllib.parse import urlparse

import pyfiglet
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
if urlparse(BASE).hostname not in ("127.0.0.1", "localhost"):
    sys.exit("Ten skrypt wolno uruchamiać tylko na własnej aplikacji (localhost).")

LOGIN_URL = BASE + "/login"
FONTS = ["standard", "big", "banner3", "doom"]       # te same czcionki co w aplikacji
NOISE = "~^"


# ===================== "OCR" dla CAPTCHA ASCII art =====================
# Bot zna czcionki (są publiczne w bibliotece pyfiglet), więc rysuje każdą cyfrę
# i porównuje z fragmentami obrazka. To pokazuje, że własna CAPTCHA tylko PODNOSI koszt ataku.

def _glyph(ch, font):
    lines = pyfiglet.figlet_format(ch, font=font).rstrip("\n").split("\n")
    return _trim(lines)


def _trim(lines):
    """Usuwa puste wiersze i puste kolumny z brzegów."""
    lines = [l.rstrip() for l in lines]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ()
    left = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
    return tuple(l[left:].rstrip() for l in lines)


TEMPLATES = {font: {_glyph(d, font): d for d in "0123456789"} for font in FONTS}


def solve_captcha(art):
    rows = html.unescape(art).split("\n")
    rows = ["".join(" " if c in NOISE else c for c in r) for r in rows]   # usuń szum
    width = max(len(r) for r in rows)
    rows = [r.ljust(width) for r in rows]
    empty = [all(r[x] == " " for r in rows) for x in range(width)]
    # podział na znaki: przerwa = co najmniej 2 puste kolumny z rzędu
    segments, start, gap = [], None, 0
    for x in range(width + 2):
        blank = x >= width or empty[x]
        if not blank:
            if start is None:
                start = x
            gap = 0
        else:
            gap += 1
            if start is not None and gap >= 2:
                segments.append((start, x - gap + 1))
                start = None
    for font, table in TEMPLATES.items():
        digits = []
        for a, b in segments:
            d = table.get(_trim([r[a:b] for r in rows]))
            if d is None:
                break
            digits.append(d)
        if len(digits) == len(segments) and digits:
            return "".join(digits)
    return None


# ===================== Komunikacja z aplikacją =====================

def get_form(session):
    page = session.get(LOGIN_URL).text
    return {
        "csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page).group(1),
        "captcha_id": re.search(r'name="captcha_id" value="([^"]+)"', page).group(1),
        "art": re.search(r'<pre class="captcha"[^>]*>(.*?)</pre>', page, re.S).group(1),
    }


def attempt(session, login, password, captcha="solve", honeypot=""):
    form = get_form(session)
    if captcha == "solve":
        answer = solve_captcha(form["art"]) or "00000"
    elif captcha == "skip":
        answer = None
    else:
        answer = captcha
    data = {"csrf_token": form["csrf_token"], "login": login, "password": password}
    if answer is not None:
        data.update(captcha_id=form["captcha_id"], captcha_answer=answer)
    if honeypot:
        data["website"] = honeypot
    r = session.post(LOGIN_URL, data=data, allow_redirects=False)
    return classify(r)


def classify(r):
    """Co bot widzi w odpowiedzi serwera."""
    if r.status_code == 302:
        return "ZALOGOWANO"
    text = r.text
    if r.status_code == 429 or "adresu IP" in text:
        return "blokada IP"
    if "zablokowan" in text:
        return "blokada konta"
    if "CAPTCHA" in text and "alert-error" in text and "Niepoprawny lub nieważny" in text:
        return "odrzucona CAPTCHA"
    return "ogólny błąd logowania"


# ===================== Scenariusze ataku =====================

def run():
    results = []
    s = requests.Session()

    print("\n[1] Prosty bot – wysyła tylko login i hasło, bez CAPTCHA")
    for pw in ["123456", "qwerty", "password"]:
        res = attempt(s, "jkowalski", pw, captcha="skip")
        print(f"    jkowalski / {pw:<10} -> {res}")
        results.append(("Prosty bot (bez CAPTCHA)", res, "CAPTCHA"))

    print("\n[2] Bot wypełniający wszystkie pola formularza (także ukryte)")
    for pw in ["haslo123", "admin1"]:
        res = attempt(s, "anowak", pw, honeypot="http://spam.example")
        print(f"    anowak / {pw:<10} -> {res}")
        results.append(("Bot wypełnia pole-pułapkę", res, "honeypot (widać w 'Próby logowania')"))

    print("\n[3] Credential stuffing – pary login/hasło z 'wycieku' innego serwisu")
    for login, pw in [("tkaminski", "Tomek1990!"), ("backup_admin", "Backup2024!"), ("kzielinska", "Kasia#123")]:
        res = attempt(s, login, pw)
        print(f"    {login} / {pw:<12} -> {res}")
        expected = "Canarytoken – alert e-mail" if login == "backup_admin" else "ogólny komunikat"
        results.append(("Credential stuffing", res, expected))

    print("\n[4] Brute force – bot łamie CAPTCHA (OCR) i zgaduje hasło jednego konta")
    solved = 0
    for i, pw in enumerate(["123456", "password1", "qwerty123", "jan123", "kowalski1", "Jan2024!", "haslo"], 1):
        form = get_form(s)
        if solve_captcha(form["art"]):
            solved += 1
        res = attempt(s, "jkowalski", pw)
        print(f"    próba {i}: jkowalski / {pw:<10} -> {res}")
        results.append(("Brute force (CAPTCHA złamana)", res, "blokada konta 15 min"))
    print(f"    CAPTCHA rozwiązana przez bota: {solved}/7")

    print("\n[5] Password spraying – jedno popularne hasło na wielu kontach")
    for login in ["anowak", "pwisniewski", "mwojcik", "tkaminski", "kzielinska", "ADMIN",
                  "admin", "test", "user", "kierownik", "ksiegowosc", "biuro"]:
        res = attempt(s, login, "Haslo123!")
        print(f"    {login:<12} / Haslo123! -> {res}")
        results.append(("Password spraying", res, "limit prób z IP"))
        if res == "blokada IP":
            print("    Bot zatrzymany limitem z adresu IP – kończę scenariusz.")
            break

    # ===================== Zestawienie =====================
    print("\n" + "=" * 90)
    print(f"{'Scenariusz':<32}{'Co zobaczył bot':<30}{'Zabezpieczenie'}")
    print("-" * 90)
    seen = set()
    for scenario, res, protection in results:
        key = (scenario, res)
        if key in seen:
            continue
        seen.add(key)
        count = sum(1 for sc, r, _ in results if sc == scenario and r == res)
        print(f"{scenario:<32}{res + f' (x{count})':<30}{protection}")
    print("=" * 90)
    logged_in = sum(1 for _, r, _ in results if r == "ZALOGOWANO")
    print(f"Udane logowania bota: {logged_in}")
    print("Szczegóły po stronie serwera: panel administratora -> 'Próby logowania'.")


if __name__ == "__main__":
    run()