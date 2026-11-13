# Moduł 1 – Identyfikacja, uwierzytelnianie i autoryzacja

Autor:Ruslana Chahsurina  
Wariant: 5 (+ zadanie dodatkowe: TOTP)

## Uruchomienie

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
flask --app app init-db
flask --app app run
```

Aplikacja: http://127.0.0.1:5000

Komenda `init-db` tworzy bazę danych i wypisuje hasła jednorazowe wszystkich kont
(ważne 24 h, przy pierwszym logowaniu wymagana jest zmiana hasła).
Nowe hasło jednorazowe dla wybranego konta: `flask --app app reset-password LOGIN`

## Konta testowe

| Login | Rola |
| --- | --- |
| ADMIN | Administrator (konto stałe) |
| jkowalski, anowak, pwisniewski | Pracownik |
| mwojcik, tkaminski, kzielinska | Gość |

## Parametry wariantu 5

| Parametr | Wartość |
| --- | --- |
| Minimalna długość hasła | 12 (zmieniana w panelu administratora) |
| Reguła dodatkowa | sprawdzanie w Have I Been Pwned (k-anonimowość) |
| Hasło jednorazowe | 14 znaków alfanumerycznych, ważne 24 h |
| Zadanie dodatkowe | TOTP (RFC 6238) z kodem QR |

## Technologia

Python 3.13, Flask, SQLite, argon2-cffi (Argon2id), Flask-WTF (CSRF),
pyotp + segno (TOTP), requests (Have I Been Pwned).

# Moduł 2 – Zabezpieczenia przed botami (wariant 5)

| Wymaganie | Realizacja |
|---|---|
| Limit błędnych logowań | N ustawiane przez administratora (domyślnie 5), blokada konta na 15 min, odliczanie na ekranie logowania |
| CAPTCHA przy logowaniu | własna, wariant 5 – liczba narysowana znakami ASCII (pyfiglet), jednorazowa, ważna 2 min |
| reCAPTCHA przy zmianie hasła | Google reCAPTCHA v2, token weryfikowany na serwerze (`siteverify`), brak tokenu = odrzucenie |
| Pułapka na boty | ukryte pole `website` w formularzu logowania (honeypot) |
| Canarytokens | konto-pułapka `backup_admin` (Web bug) + dokument Word |
| Test | `python tests/bot_attack.py` – 5 scenariuszy ataku (tylko localhost) |
| Zadanie dodatkowe | limit nieudanych prób z jednego IP niezależnie od loginu (domyślnie 20 / 15 min, HTTP 429) |

Kod: `app/protection.py`, widok logowania `app/auth.py`, panel *Próby logowania* (`/admin/attempts`).

## Konfiguracja (nie trafia do repozytorium)

Plik `instance/config.py`:

    RECAPTCHA_SITE_KEY = "..."
    RECAPTCHA_SECRET_KEY = "..."
    CANARY_ACCOUNT_URL = "..."

Bez tego pliku używane są testowe klucze Google.

Po zmianach w bazie: `flask --app app init-db`. Zdjęcie wszystkich blokad: `flask --app app unlock-all`.