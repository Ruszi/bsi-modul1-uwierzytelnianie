"""Bezpieczeństwo: hashowanie haseł i generowanie haseł jednorazowych.

Kryptografię robią sprawdzone biblioteki, NIE piszemy jej sami:
  * argon2-cffi -> hashowanie haseł algorytmem Argon2id (sól dodaje sama)
  * secrets     -> bezpieczny generator losowy (hasła jednorazowe, tokeny)
"""
import hashlib
import hmac
import secrets
import string
import time
import unicodedata
from datetime import timedelta

import requests
import pyotp

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


#  Hashowanie haseł Argon2id 

# Domyślne parametry biblioteki = zalecenia RFC 9106:
# t=3 (3 przebiegi), m=64 MiB pamięci, p=4 wątki
_hasher = PasswordHasher()


def _normalize(password):
    """Ujednolica zapis znaków Unicode (zalecenie NIST).
    Np. 'ą' wpisane na różnych klawiaturach da zawsze ten sam hash."""
    return unicodedata.normalize("NFKC", password)


def hash_password(password):
    """Zamienia hasło na hash Argon2id. Wynik zawiera: algorytm, parametry, sól i hash."""
    return _hasher.hash(_normalize(password))


def verify_password(password_hash, password):
    """Sprawdza, czy hasło pasuje do hasha. Zwraca True albo False."""
    try:
        return _hasher.verify(password_hash, _normalize(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        # biblioteka przy złym haśle rzuca wyjątek, a my chcemy po prostu False
        return False


def needs_rehash(password_hash):
    """True, jeśli hash ma stare parametry i trzeba go przeliczyć przy logowaniu."""
    return _hasher.check_needs_rehash(password_hash)


# Hash fikcyjnego hasła: sprawdzamy go, gdy login NIE istnieje,
# żeby odpowiedź trwała tyle samo co dla istniejącego konta
# (atakujący nie rozpozna po czasie, które loginy są w systemie)
DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


# ===== Hasła jednorazowe (wariant 5) =====

ONE_TIME_ALPHABET = string.ascii_letters + string.digits  # a-z, A-Z, 0-9 (alfanumeryczne)
ONE_TIME_LENGTH = 14                                      # wariant 5: 14 znaków
ONE_TIME_VALIDITY = timedelta(hours=24)                   # wariant 5: ważne 24 h


def generate_one_time_password():
    """Losuje hasło jednorazowe. secrets.choice, NIE random.choice,
    bo moduł random jest przewidywalny i nie nadaje się do haseł."""
    return "".join(secrets.choice(ONE_TIME_ALPHABET) for _ in range(ONE_TIME_LENGTH))



# ===== Polityka haseł (zgodna z NIST SP 800-63B) =====

MAX_LENGTH = 64   # NIST: system powinien przyjmować co najmniej 64 znaki

# Mała lokalna lista zakazanych haseł (sprawdzana zawsze, także bez internetu)
COMMON_PASSWORDS = {
    "123456789012", "1234567890123", "qwertyuiop123", "password1234", "password12345",
    "haslo1234567", "administrator", "zaq12wsxcde3", "1q2w3e4r5t6y", "qwerty123456",
    "iloveyou1234", "aaaaaaaaaaaa", "000000000000", "111111111111", "polska123456",
}


class HIBPError(Exception):
    """Nie udało się połączyć z API Have I Been Pwned."""


def pwned_count(password, timeout=5.0):
    """Ile razy hasło pojawiło się w wyciekach (0 = nigdy).

    K-ANONIMOWOŚĆ: do serwisu wysyłamy TYLKO 5 pierwszych znaków skrótu SHA-1.
    Serwis odsyła setki pasujących końcówek, a porównanie robimy u siebie,
    więc serwis nie wie, które hasło sprawdzamy."""
    digest = hashlib.sha1(_normalize(password).encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]          # np. "5BAA6" + reszta
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},         # fałszywe wpisy: rozmiar odpowiedzi też nic nie zdradza
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HIBPError(str(exc)) from exc

    # Odpowiedź to linie "KOŃCÓWKA:LICZBA" – szukamy naszej końcówki
    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if hmac.compare_digest(candidate.strip(), suffix):   # porównanie w stałym czasie
            return int(count.strip() or 0)
    return 0


def check_password_policy(password, *, min_length, hibp_enabled, previous_hashes):
    """Sprawdza hasło. Zwraca listę błędów – pusta lista = hasło poprawne."""
    errors = []
    length = len(_normalize(password))

    # 1. Długość (jedyne wymaganie "budowy" hasła – bez wymuszania cyfr i znaków specjalnych)
    if length < min_length:
        errors.append(f"Hasło musi mieć co najmniej {min_length} znaków (obecnie: {length}).")
    if length > MAX_LENGTH:
        errors.append(f"Hasło może mieć najwyżej {MAX_LENGTH} znaki.")

    # 2. Lista zakazanych haseł
    if _normalize(password).lower() in COMMON_PASSWORDS:
        errors.append("To hasło jest na liście haseł powszechnie używanych.")

    # 3. Nie może powtarzać obecnego ani żadnego wcześniejszego hasła
    #    (porównujemy przez verify_password, bo każdy hash ma inną sól)
    if any(verify_password(h, password) for h in previous_hashes):
        errors.append("Nowe hasło musi różnić się od poprzednich haseł.")

    # 4. Wariant 5: Have I Been Pwned (tylko gdy admin włączył i nie ma innych błędów)
    if hibp_enabled and not errors:
        try:
            count = pwned_count(password)
        except HIBPError:
            # Brak odpowiedzi = odrzucamy, NIE przepuszczamy hasła bez sprawdzenia
            errors.append("Nie udało się sprawdzić hasła w bazie wycieków. Spróbuj ponownie za chwilę.")
        else:
            if count > 0:
                errors.append(f"To hasło wystąpiło w wyciekach danych ({count} razy). Wybierz inne.")
    return errors


# ===== TOTP – weryfikacja dwuetapowa (RFC 6238) =====

TOTP_ISSUER = "Modul1 BSI"      # nazwa widoczna w aplikacji na telefonie
TOTP_INTERVAL = 30              # nowy kod co 30 sekund


def new_totp_secret():
    """Losowy sekret (Base32) – wspólny dla serwera i telefonu."""
    return pyotp.random_base32()


def totp_uri(secret, login):
    """Adres otpauth://..., który zamienimy na kod QR."""
    return pyotp.TOTP(secret).provisioning_uri(name=login, issuer_name=TOTP_ISSUER)


def verify_totp(secret, code, last_used_step):
    """Sprawdza 6-cyfrowy kod. Zwraca numer okna czasowego (sukces) albo None.

    * akceptuje okno bieżące i ±1 (zegar telefonu może się lekko różnić),
    * odrzuca okna <= ostatnio użytego -> ten sam kod nie zadziała drugi raz,
    * porównuje w stałym czasie (hmac.compare_digest), a nie przez ==."""
    code = (code or "").replace(" ", "").strip()
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    current = int(time.time()) // TOTP_INTERVAL          # numer bieżącego okna 30 s
    for step in (current - 1, current, current + 1):
        if last_used_step is not None and step <= last_used_step:
            continue                                      # kod już zużyty
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None