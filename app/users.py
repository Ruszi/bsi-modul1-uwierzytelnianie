"""Operacje na kontach użytkowników."""
from .security import ONE_TIME_VALIDITY, generate_one_time_password, hash_password
from .utils import now, to_iso


def create_user(db, login, full_name, role_name, is_system=False):
    """Tworzy konto z hasłem jednorazowym.
    Zwraca: (id nowego konta, hasło jednorazowe jawnie, data wygaśnięcia).
    Hasło jawne zwracamy TYLKO po to, żeby raz je pokazać – do bazy idzie wyłącznie hash."""
    password = generate_one_time_password()          # 14 losowych znaków
    created = now()
    expires = created + ONE_TIME_VALIDITY            # ważne 24 h
    cursor = db.execute(
        "INSERT INTO users (login, full_name, role_id, password_hash, must_change_password, "
        "one_time_expires_at, password_changed_at, is_system, created_at) "
        "SELECT ?, ?, id, ?, 1, ?, ?, ?, ? FROM roles WHERE name = ?",   # id roli szukamy po nazwie
        (login, full_name, hash_password(password), to_iso(expires), to_iso(created),
         int(is_system), to_iso(created), role_name),
    )
    return cursor.lastrowid, password, expires


def kill_sessions(db, user_id, except_hash=None):
    """Kończy sesje użytkownika. except_hash = sesja, którą zostawiamy (np. bieżąca)."""
    if except_hash:
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_hash))
    else:
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

def issue_one_time_password(db, user_id):
    """Reset hasła przez admina: nowe hasło jednorazowe + wylogowanie użytkownika."""
    password = generate_one_time_password()
    issued = now()
    expires = issued + ONE_TIME_VALIDITY
    db.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 1, "
        "one_time_expires_at = ?, password_changed_at = ? WHERE id = ?",
        (hash_password(password), to_iso(expires), to_iso(issued), user_id),
    )
    kill_sessions(db, user_id)                       # stare sesje przestają działać
    return password, expires



def set_password(db, user_id, new_password, keep_session_hash=None):
    """Zapisuje nowe hasło wybrane przez użytkownika."""
    new_hash = hash_password(new_password)
    changed = to_iso(now())
    db.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0, "
        "one_time_expires_at = NULL, password_changed_at = ? WHERE id = ?",
        (new_hash, changed, user_id),
    )
    # dopisz do historii, żeby nie dało się do niego wrócić
    db.execute("INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)",
               (user_id, new_hash, changed))
    # wyloguj z pozostałych urządzeń (bieżącą sesję zostawiamy)
    kill_sessions(db, user_id, except_hash=keep_session_hash)


def previous_hashes(db, user):
    """Obecny hash (także hasła jednorazowego) + wszystkie z historii."""
    rows = db.execute("SELECT password_hash FROM password_history WHERE user_id = ?", (user["id"],))
    return [user["password_hash"]] + [r["password_hash"] for r in rows]