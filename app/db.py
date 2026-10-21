import sqlite3

import click
from flask import current_app, g
from .utils import now, to_iso

# Model RBAC: role, uprawnienia i kto co ma 

# Role i ich opisy
ROLES = {
    "Administrator": "Zarządzanie kontami i ustawieniami bezpieczeństwa",
    "Pracownik": "Praca z dokumentami: odczyt wszystkich, tworzenie i edycja własnych",
    "Gość": "Tylko odczyt dokumentów publicznych",
}

# Wszystkie uprawnienia w systemie
PERMISSIONS = {
    "users.view": "Przeglądanie listy kont",
    "users.manage": "Dodawanie, edycja, blokowanie i usuwanie kont, reset haseł",
    "settings.manage": "Zmiana polityki haseł i ustawień sesji",
    "docs.read_public": "Odczyt dokumentów publicznych",
    "docs.read_all": "Odczyt wszystkich dokumentów",
    "docs.create": "Tworzenie dokumentów",
    "docs.edit_own": "Edycja własnych dokumentów",
}

# Macierz uprawnień: która rola dostaje które uprawnienia
# (zasada najmniejszych uprawnień: każdy ma tylko to, czego potrzebuje)
ROLE_PERMISSIONS = {
    "Administrator": ["users.view", "users.manage", "settings.manage"],
    "Pracownik": ["docs.read_public", "docs.read_all", "docs.create", "docs.edit_own"],
    "Gość": ["docs.read_public"],
}

# Ustawienia domyślne (admin zmieni je później w panelu)
DEFAULT_SETTINGS = {
    "min_length": "12",             # wariant 5: minimalna długość hasła
    "hibp_enabled": "0",            # sprawdzanie w Have I Been Pwned: 0 = wyłączone
    "password_max_age_days": "0",   # ważność hasła w dniach, 0 = bez wygasania
    "session_idle_minutes": "10",   # wylogowanie po tylu minutach bezczynności
}


# Wariant 5: 6 użytkowników testowych (login, imię i nazwisko, rola)
TEST_USERS = [
    ("jkowalski", "Jan Kowalski", "Pracownik"),
    ("anowak", "Anna Nowak", "Pracownik"),
    ("pwisniewski", "Piotr Wiśniewski", "Pracownik"),
    ("mwojcik", "Maria Wójcik", "Gość"),
    ("tkaminski", "Tomasz Kamiński", "Gość"),
    ("kzielinska", "Katarzyna Zielińska", "Gość"),
]

# Przykładowe dokumenty (tytuł, treść, publiczny?, login autora)
SAMPLE_DOCUMENTS = [
    ("Regulamin korzystania z systemu", "Dokument publiczny – widzą go wszyscy.", 1, "jkowalski"),
    ("Godziny pracy działu", "Dział pracuje od poniedziałku do piątku, 8:00–16:00.", 1, "anowak"),
    ("Plan wdrożenia", "Dokument wewnętrzny – tylko dla pracowników.", 0, "jkowalski"),
    ("Notatka ze spotkania", "Ustalenia ze spotkania zespołu – dokument wewnętrzny.", 0, "pwisniewski"),
]
#  Połączenie z bazą

def get_db():
    """Zwraca połączenie z bazą (jedno na każde żądanie przeglądarki)."""
    if "db" not in g:                                          # g = schowek na czas jednego żądania
        g.db = sqlite3.connect(current_app.config["DATABASE"]) # otwórz plik instance/app.sqlite
        g.db.row_factory = sqlite3.Row                         # wiersze jak słownik: row["login"]
        g.db.execute("PRAGMA foreign_keys = ON")               # SQLite domyślnie NIE sprawdza kluczy obcych
    return g.db


def close_db(_exc=None):
    """Zamyka połączenie na koniec żądania."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# Ustawienia 

def get_setting(key, cast=str):
    """Odczytuje ustawienie, np. get_setting("min_length", int) -> 12."""
    row = get_db().execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    value = row["value"] if row else DEFAULT_SETTINGS[key]     # brak w bazie -> wartość domyślna
    if cast is bool:
        return value == "1"                                    # "1" -> True, "0" -> False
    return cast(value)


def set_setting(key, value):
    """Zapisuje ustawienie (wstawia nowe albo nadpisuje istniejące)."""
    if isinstance(value, bool):
        value = "1" if value else "0"
    get_db().execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


# Tworzenie bazy 

def init_db():
    """Tworzy tabele i wstawia dane startowe."""
    db = get_db()

    # 1. (usuwa stare tabele i tworzy nowe)
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))

    # 2. Role
    for name, description in ROLES.items():
        db.execute("INSERT INTO roles (name, description) VALUES (?, ?)", (name, description))

    # 3. Uprawnienia
    for code, description in PERMISSIONS.items():
        db.execute("INSERT INTO permissions (code, description) VALUES (?, ?)", (code, description))

    # 4. Przypisanie uprawnień do ról (szukamy id po nazwie roli i kodzie uprawnienia)
    for role, codes in ROLE_PERMISSIONS.items():
        for code in codes:
            db.execute(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = ? AND p.code = ?",
                (role, code),
            )

    # 5. Ustawienia domyślne
    for key, value in DEFAULT_SETTINGS.items():
        set_setting(key, value)

        # 6. Konta: stałe konto ADMIN + 6 użytkowników testowych, każde z hasłem jednorazowym
    from .users import create_user                             # import tutaj, żeby uniknąć zapętlenia importów
    credentials = []                                           # lista (login, rola, hasło) do wypisania
    _, password, _ = create_user(db, "ADMIN", "Administrator systemu", "Administrator", is_system=True)
    credentials.append(("ADMIN", "Administrator", password))
    for login, full_name, role in TEST_USERS:
        _, password, _ = create_user(db, login, full_name, role)
        credentials.append((login, role, password))

    # 7. Przykładowe dokumenty (autora szukamy po loginie)
    timestamp = to_iso(now())
    for title, body, is_public, owner in SAMPLE_DOCUMENTS:
        db.execute(
            "INSERT INTO documents (title, body, is_public, owner_id, created_at, updated_at) "
            "SELECT ?, ?, ?, id, ?, ? FROM users WHERE login = ?",
            (title, body, is_public, timestamp, timestamp, owner),
        )

    db.commit()                                                # zatwierdź zmiany w pliku bazy
    return credentials                                         # oddaj hasła, żeby komenda je wypisała                                               


# Komenda w terminalu: flask --app app init-db 

@click.command("init-db")
def init_db_command():
    """Tworzy bazę od nowa i wypisuje hasła jednorazowe."""
    credentials = init_db()
    click.echo("Baza danych utworzona. Hasła jednorazowe (ważne 24 h, zmiana przy pierwszym logowaniu):\n")
    for login, role, password in credentials:
        click.echo(f"  {login:<12} {role:<14} {password}")     # wyrównanie w kolumny

@click.command("reset-password")
@click.argument("login")                                       # login podajemy po nazwie komendy
def reset_password_command(login):
    """Nadaje kontu nowe hasło jednorazowe (np. gdy hasło ADMIN wygasło)."""
    from .users import issue_one_time_password

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE login = ?", (login,)).fetchone()
    if user is None:
        raise click.ClickException("Nie ma takiego konta.")
    password, expires = issue_one_time_password(db, user["id"])   # nowe hasło + wylogowanie
    db.commit()
    click.echo(f"Nowe hasło jednorazowe dla {login}: {password} (ważne do {expires:%Y-%m-%d %H:%M} UTC)")

def init_app(app):
    """Podpina bazę pod aplikację (wywoływane w __init__.py)."""
    app.teardown_appcontext(close_db)                          # zamykaj bazę po każdym żądaniu
    app.cli.add_command(init_db_command)                       # dodaj komendę init-db
    app.cli.add_command(reset_password_command)