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