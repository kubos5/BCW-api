-- Schema iniziale di BCW-api (Cloudflare D1 / SQLite).
-- Le date sono millisecondi dall'epoca Unix.

-- Account BCW: nome utente (minuscolo) e password (PBKDF2).
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Sessioni: si salva solo l'hash SHA-256 del token.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Account Classeviva abbinati a un account BCW. Le credenziali (nome utente, password,
-- profilo) sono cifrate con AES-GCM e la chiave CREDENTIALS_KEY del server.
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ident TEXT NOT NULL,
  name TEXT,
  school TEXT,
  credentials TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (user_id, ident)
);
CREATE INDEX accounts_ident ON accounts(ident);

-- Impostazioni sincronizzate (un documento JSON per account BCW).
CREATE TABLE settings (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Orario di ogni account Classeviva abbinato (stesso JSON dell'app e del web).
CREATE TABLE timetables (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  data TEXT NOT NULL,
  version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- File allegati all'orario, divisi in pezzi (una riga di D1 non supera i 2 MB).
CREATE TABLE files (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT,
  size INTEGER NOT NULL,
  chunks INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (account_id, name)
);
CREATE INDEX files_user ON files(user_id);

CREATE TABLE file_chunks (
  file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  data BLOB NOT NULL,
  PRIMARY KEY (file_id, idx)
);

-- Tentativi per il limite di accessi e registrazioni (finestra fissa).
CREATE TABLE attempts (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
