-- Usuwanie starych tabel 
-- tabele które bedą odwoływać się do innych 
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS settings;


-- RBAC: role i uprawnienia

-- Administrator Pracownik Gość
CREATE TABLE roles (
    id          INTEGER PRIMARY KEY,      -- numer nadawany automatycznie
    name        TEXT NOT NULL UNIQUE,     -- nazwa roli, nie może się powtarzać
    description TEXT NOT NULL             -- opis roli
);

-- Pojedyncze uprawnienia, np. 'users.manage'
CREATE TABLE permissions (
    id          INTEGER PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,     -- kod sprawdzany w kodzie Pythona
    description TEXT NOT NULL             -- opis dla człowieka
);

-- Tabela łącząca: która rola ma które uprawnienie
CREATE TABLE role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,        -- klucz obcy do roles
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,  -- klucz obcy do permissions
    PRIMARY KEY (role_id, permission_id)  -- ta sama para nie może wystąpić dwa razy
);


--  Konta użytkowników 
CREATE TABLE users (
    id                   INTEGER PRIMARY KEY,
    login                TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- unikalny, 'Admin' = 'ADMIN'
    full_name            TEXT NOT NULL,                        -- imię i nazwisko
    role_id              INTEGER NOT NULL REFERENCES roles(id),-- rola użytkownika
    password_hash        TEXT NOT NULL,                        -- hash Argon2id, NIGDY samo hasło
    must_change_password INTEGER NOT NULL DEFAULT 1,           -- 1 = wymuś zmianę hasła przy logowaniu
    one_time_expires_at  TEXT,                                 -- ważność hasła jednorazowego (24 h), puste = zwykłe hasło
    password_changed_at  TEXT,                                 -- kiedy ostatnio zmieniono hasło
    is_blocked           INTEGER NOT NULL DEFAULT 0,           -- 1 = konto zablokowane przez admina
    is_system            INTEGER NOT NULL DEFAULT 0,           -- 1 = stałe konto ADMIN (nieusuwalne)
    totp_secret          TEXT,                                 -- sekret 2FA (etap 9)
    totp_enabled         INTEGER NOT NULL DEFAULT 0,           -- 1 = 2FA włączone
    totp_last_step       INTEGER,                              -- ostatnio użyty kod TOTP (blokuje ponowne użycie)
    created_at           TEXT NOT NULL                         -- data utworzenia konta
);

-- Poprzednie hasła: nowe hasło nie może powtórzyć starego
CREATE TABLE password_history (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- usunięcie konta usuwa historię
    password_hash TEXT NOT NULL,          -- hash dawnego hasła
    created_at    TEXT NOT NULL
);


-- Sesje (trzymane po stronie serwera) 
CREATE TABLE sessions (
    token_hash    TEXT PRIMARY KEY,       -- SHA-256 tokenu z ciasteczka (sam token NIE trafia do bazy)
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage         TEXT NOT NULL CHECK (stage IN ('mfa', 'full')),  -- 'mfa' = czeka na kod 2FA, 'full' = zalogowany
    mfa_attempts  INTEGER NOT NULL DEFAULT 0,  -- licznik błędnych kodów 2FA
    created_at    TEXT NOT NULL,
    last_activity TEXT NOT NULL           -- do wylogowania po bezczynności
);


-- Ustawienia zmieniane przez administratora 
-- np. min_length=12, hibp_enabled=0, session_idle_minutes=10
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,               -- nazwa ustawienia
    value TEXT NOT NULL                   -- wartość
);


-- Dokumenty: zasób do pokazania działania uprawnień =====
CREATE TABLE documents (
    id         INTEGER PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    is_public  INTEGER NOT NULL DEFAULT 0,  -- 1 = widzi też Gość, 0 = tylko Pracownik
    owner_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- autor; po jego usunięciu dokument zostaje
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);