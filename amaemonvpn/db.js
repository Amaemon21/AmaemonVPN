const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'amaemonvpn.db'));

// WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    UNIQUE NOT NULL,
    password    TEXT    NOT NULL,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    status          TEXT    DEFAULT 'inactive',  -- inactive | active | expired
    expires_at      TEXT,
    created_at      TEXT    DEFAULT (datetime('now')),
    updated_at      TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS vpn_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    peer_ip         TEXT    NOT NULL UNIQUE,  -- e.g. 10.66.66.10
    private_key     TEXT    NOT NULL,
    public_key      TEXT    NOT NULL,
    preshared_key   TEXT    NOT NULL,
    config_text     TEXT    NOT NULL,
    created_at      TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    yookassa_id     TEXT    UNIQUE,
    amount          REAL    NOT NULL,
    status          TEXT    DEFAULT 'pending',  -- pending | succeeded | cancelled
    payment_url     TEXT,
    created_at      TEXT    DEFAULT (datetime('now')),
    updated_at      TEXT    DEFAULT (datetime('now'))
  );
`);

module.exports = db;
