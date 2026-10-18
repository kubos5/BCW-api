// Adattatore che offre a `src/app.js` la stessa interfaccia di Cloudflare D1
// (`prepare().bind().first()/all()/run()` e `batch()`) sopra `node:sqlite`.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

class Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...params) {
    return new Statement(this.db, this.sql, params.map((p) => (p === undefined ? null : p)));
  }

  prepared() { return this.db.prepare(this.sql); }

  async first(column) {
    const row = this.prepared().get(...this.params);
    if (!row) return null;
    const plain = { ...row };
    return column ? plain[column] : plain;
  }

  async all() {
    return { results: this.prepared().all(...this.params).map((row) => ({ ...row })), success: true, meta: {} };
  }

  async run() { return this.runSync(); }

  runSync() {
    const info = this.prepared().run(...this.params);
    return { success: true, results: [], meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid) } };
  }
}

export class SQLiteD1 {
  constructor(path = ':memory:') {
    this.db = new DatabaseSync(path);
    // In D1 le chiavi esterne sono sempre attive, in SQLite vanno accese.
    this.db.exec('PRAGMA foreign_keys = ON');
  }

  prepare(sql) { return new Statement(this.db, sql); }

  /** Come in D1, le istruzioni di un batch sono una transazione. */
  async batch(statements) {
    this.db.exec('BEGIN');
    try {
      const results = statements.map((s) => s.runSync());
      this.db.exec('COMMIT');
      return results;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  async exec(sql) { this.db.exec(sql); }

  /** Applica le migrazioni non ancora eseguite (come `wrangler d1 migrations apply`). */
  migrate(directory) {
    this.db.exec('CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TEXT)');
    const applied = new Set(this.db.prepare('SELECT name FROM d1_migrations').all().map((r) => r.name));
    for (const name of readdirSync(directory).filter((f) => f.endsWith('.sql')).sort()) {
      if (applied.has(name)) continue;
      this.db.exec('BEGIN');
      try {
        this.db.exec(readFileSync(join(directory, name), 'utf8'));
        this.db.prepare('INSERT INTO d1_migrations (name, applied_at) VALUES (?, ?)').run(name, new Date().toISOString());
        this.db.exec('COMMIT');
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
    }
  }
}
