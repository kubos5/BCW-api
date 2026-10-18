// API di BCW: account BCW, account Classeviva abbinati, sincronizzazione di impostazioni,
// orario e file, e proxy verso Classeviva per la versione web.
//
// Il codice non dipende dalla piattaforma: riceve una `Request` e l'ambiente (`env.DB` è un
// database D1 o l'adattatore SQLite di `server/node.js`) e restituisce una `Response`.

import {
  HttpError, badRequest, corsHeaders, errorResponse, json, notFound, readBytes, readJSON, readText, unauthorized,
  withHeaders,
} from './http.js';
import {
  DEFAULT_ITERATIONS, hashPassword, newToken, open, seal, sha256Hex, uuid, verifyPassword,
} from './crypto.js';
import { classevivaLogin, isProxyPath, normalizeIdent, proxy, verifyClassevivaToken } from './classeviva.js';

export const VERSION = '1.0.0';

const DAY = 24 * 60 * 60 * 1000;
const SESSION_DAYS = 180;
const MAX_ACCOUNTS = 10;
const SETTINGS_LIMIT = 128 * 1024;
const TIMETABLE_LIMIT = 1024 * 1024;
const CHUNK_SIZE = 1024 * 1024;
/** I file appena caricati non vengono cancellati anche se l'orario non li cita ancora. */
const FILE_GRACE = 10 * 60 * 1000;

const LOGIN_LIMIT = { perUser: 10, perAddress: 50, window: 15 * 60 * 1000 };
const REGISTER_LIMIT = { perAddress: 10, window: 60 * 60 * 1000 };

function limits(env) {
  const mb = (value, fallback) => {
    const n = Number(value);
    return Math.round((Number.isFinite(n) && n > 0 ? n : fallback) * 1024 * 1024);
  };
  return {
    fileMaxBytes: mb(env.FILE_MAX_MB, 10),
    quotaBytes: mb(env.FILE_QUOTA_MB, 100),
    maxAccounts: MAX_ACCOUNTS,
  };
}

const registrationOpen = (env) => !/^(false|0|no|off)$/i.test(String(env.ALLOW_REGISTRATION ?? 'true'));

// MARK: - Validazione

/** Nome utente: 3–32 caratteri tra lettere minuscole, cifre, punto, trattino e trattino basso. */
export function normalizeUsername(value) {
  return String(value ?? '').trim().toLowerCase();
}

function validUsername(username) {
  return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(username);
}

function checkPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw badRequest('La password deve avere almeno 8 caratteri.');
  }
  if (password.length > 200) throw badRequest('La password è troppo lunga (massimo 200 caratteri).');
}

const optionalText = (value, max = 200) => (typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null);

function clientName(request, body) {
  const value = optionalText(body?.client, 60) ?? optionalText(request.headers.get('X-BCW-Client'), 60);
  return value;
}

function clientAddress(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Real-IP') || 'local';
}

// MARK: - Limite dei tentativi

async function attemptsCount(db, key, window, now) {
  const row = await db.prepare('SELECT count, window_start FROM attempts WHERE key = ?').bind(key).first();
  if (!row || now - row.window_start > window) return 0;
  return row.count;
}

function attemptStatement(db, key, window, now) {
  // Nuova finestra se quella salvata è scaduta, altrimenti un tentativo in più.
  return db.prepare(`INSERT INTO attempts (key, count, window_start) VALUES (?1, 1, ?2)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN ?2 - attempts.window_start > ?3 THEN 1 ELSE attempts.count + 1 END,
      window_start = CASE WHEN ?2 - attempts.window_start > ?3 THEN ?2 ELSE attempts.window_start END`)
    .bind(key, now, window);
}

const tooManyAttempts = () => new HttpError(429, 'too_many_attempts', 'Troppi tentativi: riprova tra qualche minuto.');

// MARK: - Sessioni

function publicUser(row) {
  return { id: row.id, username: row.username, createdAt: row.created_at };
}

async function createSession(db, userID, client, now) {
  const token = newToken();
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND expires_at < ?').bind(userID, now),
    db.prepare(`INSERT INTO sessions (token_hash, user_id, client, created_at, last_used_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)`).bind(await sha256Hex(token), userID, client, now, now, now + SESSION_DAYS * DAY),
  ]);
  return token;
}

function bearer(request) {
  const header = request.headers.get('Authorization') ?? '';
  const m = /^Bearer\s+(\S+)$/i.exec(header);
  return m ? m[1] : null;
}

/** Utente della sessione; la scadenza si sposta in avanti al massimo una volta al giorno. */
async function authenticate(ctx) {
  const token = bearer(ctx.request);
  if (!token) throw unauthorized('Serve un accesso con un account BCW.');
  const hash = await sha256Hex(token);
  const row = await ctx.db.prepare(`SELECT s.token_hash, s.expires_at, s.last_used_at, u.id, u.username, u.created_at
    FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`).bind(hash).first();
  if (!row) throw unauthorized();
  if (row.expires_at < ctx.now) {
    await ctx.db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(hash).run();
    throw unauthorized();
  }
  if (ctx.now - row.last_used_at > DAY) {
    await ctx.db.prepare('UPDATE sessions SET last_used_at = ?, expires_at = ? WHERE token_hash = ?')
      .bind(ctx.now, ctx.now + SESSION_DAYS * DAY, hash).run();
  }
  return { tokenHash: hash, user: publicUser(row) };
}

// MARK: - Account BCW

async function register(ctx) {
  const { request, db, env, now } = ctx;
  if (!registrationOpen(env)) {
    throw new HttpError(403, 'registration_closed', 'Su questo server non si possono creare nuovi account BCW.');
  }
  const body = await readJSON(request);
  const username = normalizeUsername(body.username);
  if (!validUsername(username)) {
    throw badRequest('Il nome utente deve avere da 3 a 32 caratteri: lettere, cifre, punto, trattino o trattino basso, e iniziare con una lettera o una cifra.');
  }
  checkPassword(body.password);
  const addressKey = `register:${clientAddress(request)}`;
  if (await attemptsCount(db, addressKey, REGISTER_LIMIT.window, now) >= REGISTER_LIMIT.perAddress) throw tooManyAttempts();
  await attemptStatement(db, addressKey, REGISTER_LIMIT.window, now).run();

  const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) throw new HttpError(409, 'username_taken', 'Questo nome utente è già in uso.');
  const id = uuid();
  const hash = await hashPassword(body.password, iterations(env));
  try {
    await db.prepare('INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, username, hash, now, now).run();
  } catch (error) {
    if (/UNIQUE/i.test(String(error?.message))) throw new HttpError(409, 'username_taken', 'Questo nome utente è già in uso.');
    throw error;
  }
  const token = await createSession(db, id, clientName(request, body), now);
  return json({ token, user: { id, username, createdAt: now } }, 201);
}

function iterations(env) {
  const n = Number(env.PASSWORD_ITERATIONS);
  return Number.isInteger(n) && n >= 10_000 && n <= DEFAULT_ITERATIONS ? n : DEFAULT_ITERATIONS;
}

/** Verifica la password di un utente, rifacendo l'hash se sono cambiate le iterazioni. */
async function checkUserPassword(ctx, user, password) {
  const { valid, iterations: used } = await verifyPassword(String(password ?? ''), user.password_hash);
  if (valid && used !== iterations(ctx.env)) {
    const hash = await hashPassword(String(password), iterations(ctx.env));
    await ctx.db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(hash, ctx.now, user.id).run();
  }
  return valid;
}

async function login(ctx) {
  const { request, db, now } = ctx;
  const body = await readJSON(request);
  const username = normalizeUsername(body.username);
  if (!username || typeof body.password !== 'string' || !body.password) throw badRequest('Inserisci nome utente e password.');
  const userKey = `login:${username}`;
  const addressKey = `login-ip:${clientAddress(request)}`;
  const [byUser, byAddress] = await Promise.all([
    attemptsCount(db, userKey, LOGIN_LIMIT.window, now),
    attemptsCount(db, addressKey, LOGIN_LIMIT.window, now),
  ]);
  if (byUser >= LOGIN_LIMIT.perUser || byAddress >= LOGIN_LIMIT.perAddress) throw tooManyAttempts();

  const user = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await checkUserPassword(ctx, user, body.password))) {
    await db.batch([
      attemptStatement(db, userKey, LOGIN_LIMIT.window, now),
      attemptStatement(db, addressKey, LOGIN_LIMIT.window, now),
    ]);
    throw new HttpError(401, 'invalid_credentials', 'Nome utente o password non corretti.');
  }
  await db.prepare('DELETE FROM attempts WHERE key = ?').bind(userKey).run();
  const token = await createSession(db, user.id, clientName(request, body), now);
  return json({ token, user: publicUser(user) });
}

async function logout(ctx) {
  const { tokenHash } = await authenticate(ctx);
  await ctx.db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
  return json({ ok: true });
}

async function me(ctx) {
  const { user } = await authenticate(ctx);
  const env = ctx.env;
  return json({ user, limits: limits(env) });
}

async function changePassword(ctx) {
  const { user } = await authenticate(ctx);
  const body = await readJSON(ctx.request);
  checkPassword(body.newPassword);
  const row = await ctx.db.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!row || !(await checkUserPassword(ctx, row, body.currentPassword))) {
    throw new HttpError(403, 'invalid_credentials', 'La password attuale non è corretta.');
  }
  const hash = await hashPassword(body.newPassword, iterations(ctx.env));
  await ctx.db.batch([
    ctx.db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(hash, ctx.now, user.id),
    // Cambiando password si esce da tutti i dispositivi; questo riceve una sessione nuova.
    ctx.db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
  ]);
  const token = await createSession(ctx.db, user.id, clientName(ctx.request, body), ctx.now);
  return json({ token, user });
}

async function deleteUser(ctx) {
  const { user } = await authenticate(ctx);
  const body = await readJSON(ctx.request);
  const row = await ctx.db.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!row || !(await checkUserPassword(ctx, row, body.password))) {
    throw new HttpError(403, 'invalid_credentials', 'La password non è corretta.');
  }
  const db = ctx.db;
  await db.batch([
    db.prepare('DELETE FROM file_chunks WHERE file_id IN (SELECT id FROM files WHERE user_id = ?)').bind(user.id),
    db.prepare('DELETE FROM files WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM timetables WHERE account_id IN (SELECT id FROM accounts WHERE user_id = ?)').bind(user.id),
    db.prepare('DELETE FROM accounts WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM settings WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
  ]);
  return json({ ok: true });
}

// MARK: - Account Classeviva abbinati

const credentialsContext = (userID, ident) => `${userID}:${ident}`;

async function publicAccount(env, row) {
  let credentials = null;
  try {
    credentials = await open(row.credentials, env.CREDENTIALS_KEY, credentialsContext(row.user_id, row.ident));
  } catch (error) {
    console.error('Credenziali non leggibili', row.id, error?.message);
  }
  return {
    id: row.id,
    ident: row.ident,
    name: row.name,
    school: row.school,
    credentials,
    position: row.position,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listAccounts(ctx) {
  const { user } = await authenticate(ctx);
  const { results } = await ctx.db.prepare('SELECT * FROM accounts WHERE user_id = ? ORDER BY position, created_at')
    .bind(user.id).all();
  return json({ accounts: await Promise.all(results.map((row) => publicAccount(ctx.env, row))) });
}

/**
 * Abbina un account Classeviva (o aggiorna le credenziali di uno già abbinato). Il server
 * accede a Classeviva per verificare le credenziali e ricavare profilo e nome.
 */
async function linkAccount(ctx) {
  const { user } = await authenticate(ctx);
  const body = await readJSON(ctx.request);
  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!username || !password) throw badRequest('Inserisci nome utente e password di Classeviva.');
  if (username.length > 200 || password.length > 500) throw badRequest();
  const requested = optionalText(body.ident, 40);

  const result = await classevivaLogin(ctx.fetch, { username, password, ident: requested });
  const ident = result.ident;
  const credentials = { username, password, ident };
  const sealed = await seal(credentials, ctx.env.CREDENTIALS_KEY, credentialsContext(user.id, ident));
  const db = ctx.db;
  const existing = await db.prepare('SELECT * FROM accounts WHERE user_id = ? AND ident = ?').bind(user.id, ident).first();
  const name = result.name ?? optionalText(body.name) ?? existing?.name ?? username;
  const school = optionalText(body.school) ?? existing?.school ?? null;
  if (existing) {
    await db.prepare('UPDATE accounts SET credentials = ?, name = ?, school = ?, updated_at = ? WHERE id = ?')
      .bind(sealed, name, school, ctx.now, existing.id).run();
    const row = await db.prepare('SELECT * FROM accounts WHERE id = ?').bind(existing.id).first();
    return json({ account: await publicAccount(ctx.env, row), created: false });
  }
  const count = await db.prepare('SELECT COUNT(*) AS n, COALESCE(MAX(position), -1) AS last FROM accounts WHERE user_id = ?')
    .bind(user.id).first();
  if (count.n >= MAX_ACCOUNTS) {
    throw new HttpError(409, 'limit_reached', `Puoi abbinare al massimo ${MAX_ACCOUNTS} account Classeviva.`);
  }
  const id = uuid();
  await db.prepare(`INSERT INTO accounts (id, user_id, ident, name, school, credentials, position, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, user.id, ident, name, school, sealed, count.last + 1, ctx.now, ctx.now).run();
  const row = await db.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first();
  return json({ account: await publicAccount(ctx.env, row), created: true }, 201);
}

async function ownedAccount(ctx, userID, id) {
  const row = await ctx.db.prepare('SELECT * FROM accounts WHERE id = ? AND user_id = ?').bind(id, userID).first();
  if (!row) throw notFound('Account Classeviva non abbinato a questo account BCW.');
  return row;
}

/** Aggiorna nome e scuola mostrati (le app li leggono dalla scheda dello studente). */
async function updateAccount(ctx) {
  const { user } = await authenticate(ctx);
  const row = await ownedAccount(ctx, user.id, ctx.params.id);
  const body = await readJSON(ctx.request);
  const name = 'name' in body ? (optionalText(body.name) ?? row.name) : row.name;
  const school = 'school' in body ? optionalText(body.school) : row.school;
  const position = Number.isInteger(body.position) ? body.position : row.position;
  await ctx.db.prepare('UPDATE accounts SET name = ?, school = ?, position = ?, updated_at = ? WHERE id = ?')
    .bind(name, school, position, ctx.now, row.id).run();
  return json({ account: await publicAccount(ctx.env, { ...row, name, school, position, updated_at: ctx.now }) });
}

function accountDeletion(db, accountID) {
  return [
    db.prepare('DELETE FROM file_chunks WHERE file_id IN (SELECT id FROM files WHERE account_id = ?)').bind(accountID),
    db.prepare('DELETE FROM files WHERE account_id = ?').bind(accountID),
    db.prepare('DELETE FROM timetables WHERE account_id = ?').bind(accountID),
    db.prepare('DELETE FROM accounts WHERE id = ?').bind(accountID),
  ];
}

async function unlinkAccount(ctx) {
  const { user } = await authenticate(ctx);
  const row = await ownedAccount(ctx, user.id, ctx.params.id);
  await ctx.db.batch(accountDeletion(ctx.db, row.id));
  return json({ ok: true });
}

// MARK: - Lato Classeviva: account BCW a cui è abbinato un profilo

async function classevivaIdentity(ctx) {
  const ident = ctx.request.headers.get('X-Classeviva-Ident');
  const token = ctx.request.headers.get('X-Classeviva-Token');
  return verifyClassevivaToken(ctx.fetch, ident, token);
}

async function listLinks(ctx) {
  const ident = await classevivaIdentity(ctx);
  const { results } = await ctx.db.prepare(`SELECT a.id, a.created_at, u.username FROM accounts a
    JOIN users u ON u.id = a.user_id WHERE a.ident = ? ORDER BY a.created_at`).bind(ident).all();
  return json({ ident, links: results.map((r) => ({ id: r.id, username: r.username, linkedAt: r.created_at })) });
}

async function removeLink(ctx) {
  const ident = await classevivaIdentity(ctx);
  const row = await ctx.db.prepare('SELECT id FROM accounts WHERE id = ? AND ident = ?').bind(ctx.params.id, ident).first();
  if (!row) throw notFound('Questo profilo non è abbinato a quell\'account BCW.');
  await ctx.db.batch(accountDeletion(ctx.db, row.id));
  return json({ ok: true });
}

async function removeAllLinks(ctx) {
  const ident = await classevivaIdentity(ctx);
  const { results } = await ctx.db.prepare('SELECT id FROM accounts WHERE ident = ?').bind(ident).all();
  if (results.length) await ctx.db.batch(results.flatMap((r) => accountDeletion(ctx.db, r.id)));
  return json({ ok: true, removed: results.length });
}

// MARK: - Sincronizzazione (impostazioni e orario)

function documentResponse(row) {
  if (!row) return json({ data: null, version: 0, updatedAt: null });
  let data = null;
  try { data = JSON.parse(row.data); } catch { /* documento rovinato: come se mancasse */ }
  return json({ data, version: row.version, updatedAt: row.updated_at });
}

/**
 * Salva un documento solo se la versione sul server è ancora `baseVersion`; altrimenti
 * risponde 409 con il documento attuale, che l'app unisce alle sue modifiche.
 */
async function putDocument(ctx, { table, keyColumn, key, limit }) {
  const text = await readText(ctx.request, limit + 1024);
  let body;
  try { body = JSON.parse(text); } catch { throw badRequest('Il corpo della richiesta non è JSON valido.'); }
  if (!body || typeof body !== 'object' || !body.data || typeof body.data !== 'object' || Array.isArray(body.data)) {
    throw badRequest('Manca il documento da salvare.');
  }
  const baseVersion = Number.isInteger(body.baseVersion) && body.baseVersion >= 0 ? body.baseVersion : 0;
  const data = JSON.stringify(body.data);
  if (data.length > limit) throw new HttpError(413, 'too_large', 'Il documento è troppo grande.');
  const db = ctx.db;
  const result = baseVersion === 0
    ? await db.prepare(`INSERT INTO ${table} (${keyColumn}, data, version, updated_at) VALUES (?, ?, 1, ?)
        ON CONFLICT(${keyColumn}) DO NOTHING`).bind(key, data, ctx.now).run()
    : await db.prepare(`UPDATE ${table} SET data = ?, version = version + 1, updated_at = ?
        WHERE ${keyColumn} = ? AND version = ?`).bind(data, ctx.now, key, baseVersion).run();
  if (!result.meta?.changes) {
    const current = await db.prepare(`SELECT * FROM ${table} WHERE ${keyColumn} = ?`).bind(key).first();
    let currentData = null;
    try { currentData = current ? JSON.parse(current.data) : null; } catch { /* ignorato */ }
    throw new HttpError(409, 'conflict', 'Il documento è cambiato su un altro dispositivo.', {
      data: currentData, version: current?.version ?? 0, updatedAt: current?.updated_at ?? null,
    });
  }
  return { version: baseVersion + 1, updatedAt: ctx.now, data: body.data };
}

async function getSettings(ctx) {
  const { user } = await authenticate(ctx);
  return documentResponse(await ctx.db.prepare('SELECT * FROM settings WHERE user_id = ?').bind(user.id).first());
}

async function putSettings(ctx) {
  const { user } = await authenticate(ctx);
  const saved = await putDocument(ctx, { table: 'settings', keyColumn: 'user_id', key: user.id, limit: SETTINGS_LIMIT });
  return json({ version: saved.version, updatedAt: saved.updatedAt });
}

async function getTimetable(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  return documentResponse(await ctx.db.prepare('SELECT * FROM timetables WHERE account_id = ?').bind(account.id).first());
}

async function putTimetable(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  const saved = await putDocument(ctx, { table: 'timetables', keyColumn: 'account_id', key: account.id, limit: TIMETABLE_LIMIT });
  await removeUnreferencedFiles(ctx, account.id, referencedFiles(saved.data));
  return json({ version: saved.version, updatedAt: saved.updatedAt });
}

/** Nomi dei file citati da un orario (allegati degli eventi e dei singoli giorni). */
export function referencedFiles(timetable) {
  const names = new Set();
  const add = (list) => {
    if (!Array.isArray(list)) return;
    for (const a of list) if (a && typeof a.storedName === 'string') names.add(a.storedName);
  };
  for (const e of Array.isArray(timetable?.entries) ? timetable.entries : []) add(e?.attachments);
  const occurrences = timetable?.occurrences;
  if (occurrences && typeof occurrences === 'object') for (const o of Object.values(occurrences)) add(o?.attachments);
  return names;
}

async function removeUnreferencedFiles(ctx, accountID, referenced) {
  const { results } = await ctx.db.prepare('SELECT id, name, created_at FROM files WHERE account_id = ?').bind(accountID).all();
  const stale = results.filter((f) => !referenced.has(f.name) && ctx.now - f.created_at > FILE_GRACE).slice(0, 10);
  if (!stale.length) return;
  await ctx.db.batch(stale.flatMap((f) => [
    ctx.db.prepare('DELETE FROM file_chunks WHERE file_id = ?').bind(f.id),
    ctx.db.prepare('DELETE FROM files WHERE id = ?').bind(f.id),
  ]));
}

// MARK: - File dell'orario

const validFileName = (name) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name);

function fileName(ctx) {
  let name;
  try { name = decodeURIComponent(ctx.params.name); } catch { name = ''; }
  if (!validFileName(name)) throw badRequest('Nome del file non valido.');
  return name;
}

async function usage(db, userID) {
  const row = await db.prepare('SELECT COALESCE(SUM(size), 0) AS used FROM files WHERE user_id = ?').bind(userID).first();
  return row.used;
}

async function listFiles(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  const { results } = await ctx.db.prepare('SELECT name, type, size, created_at FROM files WHERE account_id = ? ORDER BY name')
    .bind(account.id).all();
  return json({
    files: results.map((f) => ({ name: f.name, type: f.type, size: f.size, createdAt: f.created_at })),
    used: await usage(ctx.db, user.id),
    quota: limits(ctx.env).quotaBytes,
  });
}

async function putFile(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  const name = fileName(ctx);
  const { fileMaxBytes, quotaBytes } = limits(ctx.env);
  const bytes = await readBytes(ctx.request, fileMaxBytes);
  const db = ctx.db;
  const previous = await db.prepare('SELECT id, size FROM files WHERE account_id = ? AND name = ?').bind(account.id, name).first();
  const used = (await usage(db, user.id)) - (previous?.size ?? 0);
  if (used + bytes.byteLength > quotaBytes) {
    throw new HttpError(413, 'quota_exceeded', 'Spazio esaurito: lo spazio per i file dell\'orario di questo account BCW è pieno.');
  }
  const rawType = (ctx.request.headers.get('Content-Type') ?? '').split(';')[0].trim().toLowerCase();
  const type = /^[\w.+-]+\/[\w.+-]+$/.test(rawType) ? rawType : null;
  const id = uuid();
  const chunks = Math.max(1, Math.ceil(bytes.byteLength / CHUNK_SIZE));
  const statements = [];
  if (previous) {
    statements.push(db.prepare('DELETE FROM file_chunks WHERE file_id = ?').bind(previous.id));
    statements.push(db.prepare('DELETE FROM files WHERE id = ?').bind(previous.id));
  }
  statements.push(db.prepare(`INSERT INTO files (id, account_id, user_id, name, type, size, chunks, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, account.id, user.id, name, type, bytes.byteLength, chunks, ctx.now));
  for (let i = 0; i < chunks; i++) {
    statements.push(db.prepare('INSERT INTO file_chunks (file_id, idx, data) VALUES (?, ?, ?)')
      .bind(id, i, bytes.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)));
  }
  await db.batch(statements);
  return json({ name, size: bytes.byteLength, type, createdAt: ctx.now }, previous ? 200 : 201);
}

async function getFile(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  const name = fileName(ctx);
  const file = await ctx.db.prepare('SELECT * FROM files WHERE account_id = ? AND name = ?').bind(account.id, name).first();
  if (!file) throw notFound('File non trovato sul server.');
  const out = new Uint8Array(file.size);
  let offset = 0;
  for (let i = 0; i < file.chunks; i++) {
    const chunk = await ctx.db.prepare('SELECT data FROM file_chunks WHERE file_id = ? AND idx = ?').bind(file.id, i).first();
    if (!chunk) throw notFound('Il file sul server è incompleto.');
    const data = toBytes(chunk.data);
    out.set(data.subarray(0, Math.max(0, file.size - offset)), offset);
    offset += data.byteLength;
  }
  return new Response(out, {
    headers: {
      'Content-Type': file.type || 'application/octet-stream',
      'Content-Length': String(file.size),
      'Cache-Control': 'private, max-age=31536000, immutable',
    },
  });
}

/** D1 restituisce i BLOB come array di numeri, SQLite di Node come `Uint8Array`. */
function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error('Formato del file non riconosciuto.');
}

async function deleteFile(ctx) {
  const { user } = await authenticate(ctx);
  const account = await ownedAccount(ctx, user.id, ctx.params.id);
  const name = fileName(ctx);
  const file = await ctx.db.prepare('SELECT id FROM files WHERE account_id = ? AND name = ?').bind(account.id, name).first();
  if (file) {
    await ctx.db.batch([
      ctx.db.prepare('DELETE FROM file_chunks WHERE file_id = ?').bind(file.id),
      ctx.db.prepare('DELETE FROM files WHERE id = ?').bind(file.id),
    ]);
  }
  return json({ ok: true });
}

// MARK: - Instradamento

function info(ctx) {
  return json({
    name: 'BCW API',
    version: VERSION,
    registration: registrationOpen(ctx.env),
    limits: limits(ctx.env),
  });
}

const routes = [
  ['GET', /^\/$/, info],
  ['POST', /^\/auth\/register$/, register],
  ['POST', /^\/auth\/login$/, login],
  ['POST', /^\/auth\/logout$/, logout],
  ['GET', /^\/me$/, me],
  ['DELETE', /^\/me$/, deleteUser],
  ['PUT', /^\/me\/password$/, changePassword],
  ['GET', /^\/accounts$/, listAccounts],
  ['POST', /^\/accounts$/, linkAccount],
  ['PATCH', /^\/accounts\/(?<id>[\w-]+)$/, updateAccount],
  ['DELETE', /^\/accounts\/(?<id>[\w-]+)$/, unlinkAccount],
  ['GET', /^\/sync\/settings$/, getSettings],
  ['PUT', /^\/sync\/settings$/, putSettings],
  ['GET', /^\/sync\/timetable\/(?<id>[\w-]+)$/, getTimetable],
  ['PUT', /^\/sync\/timetable\/(?<id>[\w-]+)$/, putTimetable],
  ['GET', /^\/files\/(?<id>[\w-]+)$/, listFiles],
  ['GET', /^\/files\/(?<id>[\w-]+)\/(?<name>[^/]+)$/, getFile],
  ['PUT', /^\/files\/(?<id>[\w-]+)\/(?<name>[^/]+)$/, putFile],
  ['DELETE', /^\/files\/(?<id>[\w-]+)\/(?<name>[^/]+)$/, deleteFile],
  ['GET', /^\/classeviva\/links$/, listLinks],
  ['DELETE', /^\/classeviva\/links$/, removeAllLinks],
  ['DELETE', /^\/classeviva\/links\/(?<id>[\w-]+)$/, removeLink],
];

/**
 * Crea il gestore delle richieste. `fetch` è quello usato verso Classeviva (sostituibile
 * nelle prove), `now` l'orologio.
 */
export function createApp({ fetch: fetchImpl = (...args) => fetch(...args), now = () => Date.now() } = {}) {
  return async function handle(request, env) {
    const cors = corsHeaders(request, env);
    const url = new URL(request.url);
    // Le app possono pubblicare l'API sotto un percorso (es. /bcw): conta solo quello dopo.
    const base = String(env.BASE_PATH ?? '').replace(/\/+$/, '');
    let pathname = url.pathname;
    if (base && (pathname === base || pathname.startsWith(`${base}/`))) pathname = pathname.slice(base.length) || '/';

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (isProxyPath(pathname)) return proxy(request, env, fetchImpl, pathname);

    const marks = { ...cors, 'X-BCW-API': '1' };
    try {
      for (const [method, pattern, handler] of routes) {
        const match = pattern.exec(pathname);
        if (!match) continue;
        if (request.method !== method && !(request.method === 'HEAD' && method === 'GET')) continue;
        if (!env.DB) throw new Error('Manca il database: collega un database D1 con il nome DB.');
        const ctx = { request, env, db: env.DB, params: match.groups ?? {}, fetch: fetchImpl, now: now() };
        return withHeaders(await handler(ctx), marks);
      }
      const known = routes.some(([, pattern]) => pattern.test(pathname));
      throw known
        ? new HttpError(405, 'method_not_allowed', 'Metodo non consentito.')
        : notFound('Percorso sconosciuto.');
    } catch (error) {
      return withHeaders(errorResponse(error), marks);
    }
  };
}
