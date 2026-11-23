"""MODUŁ 3: dziennik zdarzeń bezpieczeństwa (wariant 5).

Wariant 5:
  * format zapisu: plik JSON dokładnie JSON Lines: jeden obiekt JSON w jednej linii
    (instance/security_log.jsonl). Nowy wpis tylko DOPISUJEMY na końcu niczego nie nadpisujemy.
  * integralność: SHA-256 CAŁEGO pliku dziennika liczony po każdym wpisie i zapisywany
    w osobnym pliku (instance/security_log.sha256). Każda linia tego pliku to:
    "<liczba wpisów> <skrót SHA-256 całego dziennika po tylu wpisach>".
    Ostatnia linia = skrót aktualnego pliku. Dzięki historii skrótów weryfikacja
    potrafi wskazać, od którego wpisu dziennik się nie zgadza.
  * reguła detekcji z wariantu: >= 3 odmowy dostępu dla jednego użytkownika w ciągu 10 minut
    (+ reguła wspólna: >= 5 nieudanych logowań na jedno konto w ciągu 5 minut).
  * kanał alertu: osobny plik alertów (instance/alerts.jsonl).

Zasady (OWASP Logging Cheat Sheet):
  * czas zawsze w UTC,
  * NIGDY nie zapisujemy haseł (także błędnych), tokenów sesji ani kluczy,
  * dane od użytkownika są czyszczone (ochrona przed log injection),
  * dziennika nie da się wyłączyć ani edytować z poziomu aplikacji.
"""
import hashlib
import json
import threading
from datetime import timedelta
from pathlib import Path

from flask import current_app, g, has_request_context, request

from .utils import from_iso, now, to_iso

LOG_NAME = "security_log.jsonl"         # dziennik zdarzeń (JSON Lines)
HASH_NAME = "security_log.sha256"       # skróty SHA-256 całego dziennika
ALERTS_NAME = "alerts.jsonl"            # kanał alertów z wariantu 5: osobny plik

# Typy zdarzeń: kod zapisywany w dzienniku -> opis do filtra w przeglądarce logów
EVENT_TYPES = {
    "LOGIN_SUCCESS": "Udane logowanie",
    "LOGIN_FAILED": "Nieudane logowanie",
    "LOGOUT": "Wylogowanie",
    "ACCOUNT_LOCKED": "Blokada konta po błędnych logowaniach",
    "CANARY_LOGIN": "Użycie konta-pułapki",
    "PASSWORD_CHANGE": "Zmiana hasła",
    "PASSWORD_RESET": "Reset hasła przez administratora",
    "USER_CREATE": "Utworzenie konta",
    "USER_UPDATE": "Edycja konta",
    "ROLE_CHANGE": "Zmiana roli",
    "USER_BLOCK": "Zablokowanie konta",
    "USER_UNBLOCK": "Odblokowanie konta",
    "USER_DELETE": "Usunięcie konta",
    "MFA_CHANGE": "Zmiana ustawień 2FA",
    "SETTINGS_CHANGE": "Zmiana ustawień bezpieczeństwa",
    "ACCESS_DENIED": "Odmowa dostępu",
    "LOG_VIEW": "Podgląd dziennika",
    "LOG_EXPORT": "Eksport dziennika",
    "LOG_VERIFY": "Weryfikacja integralności dziennika",
    "ALERT": "Alert",
}

SUCCESS, FAILURE = "sukces", "błąd"

# Reguły detekcji: (typ zdarzenia, próg, okno w minutach, nazwa reguły)
RULE_FAILED_LOGINS = ("LOGIN_FAILED", 5, 5, "≥5 nieudanych logowań na jedno konto w 5 min")
RULE_ACCESS_DENIED = ("ACCESS_DENIED", 3, 10, "≥3 odmowy dostępu dla jednego użytkownika w 10 min")

_lock = threading.Lock()    # serwer Flask obsługuje żądania równolegle – zapis po kolei


# ===================== ŚCIEŻKI PLIKÓW =====================

def _path(name):
    """Pliki dziennika leżą w instance/ – ten folder NIE trafia do repozytorium."""
    return Path(current_app.instance_path) / name


# ===================== OCHRONA PRZED LOG INJECTION =====================

def clean(value, limit=200):
    """Czyści tekst od użytkownika przed zapisem do dziennika:
    usuwa znaki sterujące (np. \\n, \\r), żeby nie dało się dopisać sfałszowanej linii,
    i przycina długość. Dodatkowo json.dumps i tak zamienia znaki specjalne na \\n, \\" itd."""
    text = "" if value is None else str(value)
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return text[:limit]


# ===================== ZAPIS WPISU =====================

def _client_ip():
    if not has_request_context():
        return "-"                              # zdarzenie z terminala (np. komenda flask)
    return request.remote_addr or "-"           # NIE ufamy nagłówkowi X-Forwarded-For


def _current_login():
    user = g.get("user") if has_request_context() else None
    return user["login"] if user is not None else "-"


def _sha256_file(path):
    """SHA-256 całego pliku (czytany kawałkami)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def log_event(action, description, result=SUCCESS, user=None, check_rules=True):
    """Dopisuje wpis do dziennika: kto, co, kiedy, skąd, z jakim skutkiem.

    action      – kod z EVENT_TYPES, np. "LOGIN_FAILED"
    description – opis zdarzenia (BEZ haseł i tokenów!)
    result      – "sukces" albo "błąd"
    user        – login, którego dotyczy zdarzenie (domyślnie: zalogowany użytkownik)
    """
    log_path, hash_path = _path(LOG_NAME), _path(HASH_NAME)
    with _lock:
        # numer wpisu = liczba skrótów zapisanych przez aplikację + 1
        # (gdyby ktoś usunął wpis z pliku, numeracja i tak idzie dalej – widać lukę)
        count = _count_lines(hash_path)
        entry = {
            "id": count + 1,                                    # numer kolejny wpisu
            "timestamp": to_iso(now()),                         # KIEDY (UTC)
            "user": clean(user if user is not None else _current_login(), 64),   # KTO
            "ip": clean(_client_ip(), 64),                      # SKĄD
            "action": action,                                   # CO (typ)
            "description": clean(description, 300),             # CO (szczegóły)
            "result": result,                                   # Z JAKIM SKUTKIEM
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"     # jeden wpis = jedna linia JSON
        with open(log_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
        # Wariant 5: po KAŻDYM wpisie liczymy SHA-256 całego pliku i zapisujemy w osobnym pliku
        with open(hash_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"{entry['id']} {_sha256_file(log_path)}\n")

    if check_rules and action in (RULE_FAILED_LOGINS[0], RULE_ACCESS_DENIED[0]):
        _check_rules(action, entry["user"])
    return entry


def _count_lines(path):
    if not path.exists():
        return 0
    with open(path, "rb") as f:
        return sum(1 for _ in f)


# ===================== ODCZYT =====================

def read_entries():
    """Wszystkie wpisy dziennika (od najstarszego). Uszkodzone linie są pomijane."""
    path = _path(LOG_NAME)
    entries = []
    if not path.exists():
        return entries
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries


def filter_entries(entries, user="", action="", date_from="", date_to=""):
    """Filtr przeglądarki logów: użytkownik (fragment loginu), typ zdarzenia, zakres dat (RRRR-MM-DD)."""
    result = []
    for e in entries:
        day = e.get("timestamp", "")[:10]                       # "2026-11-21"
        if user and user.lower() not in e.get("user", "").lower():
            continue
        if action and e.get("action") != action:
            continue
        if date_from and day < date_from:
            continue
        if date_to and day > date_to:
            continue
        result.append(e)
    return result


# ===================== WERYFIKACJA INTEGRALNOŚCI =====================

def verify_integrity():
    """Liczy SHA-256 dziennika od nowa i porównuje z zapisanymi skrótami.

    Zwraca słownik: ok (True/False), message (opis wyniku), entries (liczba wpisów),
    bad_entry (numer pierwszego wpisu, który się nie zgadza, albo None).
    """
    log_path, hash_path = _path(LOG_NAME), _path(HASH_NAME)
    if not log_path.exists() and not hash_path.exists():
        return {"ok": True, "entries": 0, "bad_entry": None, "message": "Dziennik jest pusty."}
    if not hash_path.exists():
        return {"ok": False, "entries": _count_lines(log_path), "bad_entry": None,
                "message": "Brak pliku ze skrótami – nie da się potwierdzić integralności."}

    # zapisane skróty: lista (liczba wpisów, skrót)
    stored = []
    with open(hash_path, encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit():
                stored.append((int(parts[0]), parts[1]))

    lines = log_path.read_bytes().splitlines(keepends=True) if log_path.exists() else []

    # 1. Najważniejsze sprawdzenie (wariant 5): skrót CAŁEGO pliku = ostatni zapisany skrót?
    current = hashlib.sha256(b"".join(lines)).hexdigest()
    last_ok = bool(stored) and stored[-1] == (len(lines), current)

    # 2. Szukamy miejsca ingerencji: liczymy skrót narastająco, linia po linii
    digest = hashlib.sha256()
    for number, line in enumerate(lines, start=1):
        digest.update(line)
        if number > len(stored):
            return {"ok": False, "entries": len(lines), "bad_entry": number,
                    "message": f"Wykryto ingerencję: wpis nr {number} został dopisany poza aplikacją "
                               f"(brak dla niego skrótu)."}
        if stored[number - 1] != (number, digest.hexdigest()):
            return {"ok": False, "entries": len(lines), "bad_entry": number,
                    "message": f"Wykryto ingerencję: dziennik nie zgadza się od wpisu nr {number} "
                               f"(wpis zmieniony, usunięty albo wstawiony)."}
    if len(lines) < len(stored):
        return {"ok": False, "entries": len(lines), "bad_entry": len(lines) + 1,
                "message": f"Wykryto ingerencję: usunięto wpisy od nr {len(lines) + 1} "
                           f"(zapisano {len(stored)} skrótów, w dzienniku jest {len(lines)} wpisów)."}
    if not last_ok:
        return {"ok": False, "entries": len(lines), "bad_entry": None,
                "message": "Wykryto ingerencję: skrót całego dziennika nie zgadza się z zapisanym."}
    return {"ok": True, "entries": len(lines), "bad_entry": None,
            "message": f"Dziennik nienaruszony – {len(lines)} wpisów, SHA-256: {current}"}


# ===================== REGUŁY DETEKCJI I ALERTY =====================

def _recent(entries, action, user, minutes):
    """Wpisy danego typu dla danego użytkownika z ostatnich `minutes` minut."""
    since = now() - timedelta(minutes=minutes)
    return [e for e in entries
            if e.get("action") == action and e.get("user") == user
            and from_iso(e["timestamp"]) >= since]


def _check_rules(action, user):
    """Uruchamiana po zapisaniu zdarzenia LOGIN_FAILED lub ACCESS_DENIED."""
    for rule_action, threshold, minutes, name in (RULE_FAILED_LOGINS, RULE_ACCESS_DENIED):
        if action != rule_action or user in ("", "-"):
            continue
        entries = read_entries()
        hits = _recent(entries, rule_action, user, minutes)
        if len(hits) < threshold:
            continue
        # jeden alert na okno czasowe – bez zasypywania administratora powtórkami
        already = [e for e in _recent(entries, "ALERT", user, minutes) if name in e.get("description", "")]
        if already:
            continue
        raise_alert(name, user, f"liczba zdarzeń {rule_action}: {len(hits)} w ciągu {minutes} min")


def raise_alert(rule, user, details):
    """Alert trafia (1) do dziennika i (2) do osobnego pliku alertów – kanał z wariantu 5."""
    entry = log_event("ALERT", f"Reguła: {rule}. {details}", FAILURE, user=user, check_rules=False)
    alert = {"timestamp": entry["timestamp"], "rule": rule, "user": entry["user"],
             "ip": entry["ip"], "details": clean(details), "log_entry": entry["id"]}
    with _lock, open(_path(ALERTS_NAME), "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    current_app.logger.warning("ALERT: %s (%s)", rule, entry["user"])   # także w konsoli serwera


def read_alerts():
    path = _path(ALERTS_NAME)
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
