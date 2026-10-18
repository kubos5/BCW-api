// Prove dell'API con SQLite in memoria e un Classeviva finto. `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createApp, referencedFiles } from '../src/app.js';
import { SQLiteD1 } from '../server/sqlite.js';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const KEY = Buffer.alloc(32, 7).toString('base64');

/** Classeviva finto: due studenti e un genitore con due figli. */
const people = {
  'mario.rossi': { password: 'segreta1', ident: 'S1234567X', firstName: 'MARIO', lastName: 'ROSSI' },
  'anna.bianchi': { password: 'segreta2', ident: 'S7654321Y', firstName: 'ANNA', lastName: 'BIANCHI' },
  genitore: {
    password: 'segreta3',
    choices: [
      { ident: 'G1111111A', name: 'Luca Verdi', school: 'Liceo' },
      { ident: 'G2222222B', name: 'Sara Verdi', school: 'Liceo' },
    ],
  },
};

function fakeClassevivaFetch(calls = []) {
  return async (url, init = {}) => {
    calls.push(url);
    const { pathname } = new URL(url);
    if (pathname.endsWith('/auth/login')) {
      const body = JSON.parse(init.body);
      const person = people[body.uid];
      if (!person || person.password !== body.pass) {
        return Response.json({ error: '422 Unprocessable Entity', message: 'wrong credentials' }, { status: 422 });
      }
      if (person.choices && !body.ident) return Response.json({ choices: person.choices });
      const ident = body.ident ?? person.ident;
      return Response.json({ ident, firstName: person.firstName ?? 'LUCA', lastName: person.lastName ?? 'VERDI', token: `tok-${ident}` });
    }
    const card = /\/students\/(\d+)\/card$/.exec(pathname);
    if (card) {
      const token = new Headers(init.headers).get('Z-Auth-Token');
      if (!token || token.replace(/\D/g, '') !== card[1]) return Response.json({ error: 'forbidden' }, { status: 403 });
      return Response.json({ card: { ident: token.slice(4), firstName: 'X', lastName: 'Y' } });
    }
    if (pathname.includes('/students/')) return Response.json({ ok: true, path: pathname, method: init.method ?? 'GET' });
    return new Response('not found', { status: 404 });
  };
}

function setup({ env = {}, clock } = {}) {
  const db = new SQLiteD1();
  db.migrate(MIGRATIONS);
  const calls = [];
  let time = clock ?? 1_800_000_000_000;
  const handle = createApp({ fetch: fakeClassevivaFetch(calls), now: () => time });
  const fullEnv = { DB: db, CREDENTIALS_KEY: KEY, PASSWORD_ITERATIONS: '10000', ...env };
  const call = async (method, path, { body, token, headers = {}, raw } = {}) => {
    const init = { method, headers: { ...headers } };
    if (token) init.headers.Authorization = `Bearer ${token}`;
    if (raw !== undefined) init.body = raw;
    else if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] = 'application/json';
    }
    const response = await handle(new Request(`https://api.test${path}`, init), fullEnv);
    const type = response.headers.get('Content-Type') ?? '';
    const data = type.includes('json') ? await response.json() : new Uint8Array(await response.arrayBuffer());
    return { status: response.status, data, headers: response.headers };
  };
  return { db, call, calls, advance: (ms) => { time += ms; } };
}

async function registered(call, username = 'giulia', password = 'password-bcw') {
  const r = await call('POST', '/auth/register', { body: { username, password } });
  assert.equal(r.status, 201, JSON.stringify(r.data));
  return r.data.token;
}

test('registrazione, accesso, uscita', async () => {
  const { call } = setup();
  const info = await call('GET', '/');
  assert.equal(info.data.name, 'BCW API');
  assert.equal(info.data.registration, true);

  const token = await registered(call, 'Giulia.E');
  const me = await call('GET', '/me', { token });
  assert.equal(me.status, 200);
  assert.equal(me.data.user.username, 'giulia.e');

  assert.equal((await call('POST', '/auth/register', { body: { username: 'giulia.e', password: 'altra-password' } })).data.error, 'username_taken');
  assert.equal((await call('POST', '/auth/register', { body: { username: 'ab', password: 'password-bcw' } })).status, 400);
  assert.equal((await call('POST', '/auth/register', { body: { username: 'ciao', password: 'corta' } })).status, 400);

  const wrong = await call('POST', '/auth/login', { body: { username: 'giulia.e', password: 'sbagliata' } });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.data.error, 'invalid_credentials');
  const ok = await call('POST', '/auth/login', { body: { username: ' GIULIA.E ', password: 'password-bcw' } });
  assert.equal(ok.status, 200);
  assert.ok(ok.data.token);

  assert.equal((await call('POST', '/auth/logout', { token: ok.data.token })).status, 200);
  assert.equal((await call('GET', '/me', { token: ok.data.token })).status, 401);
  assert.equal((await call('GET', '/me', { token })).status, 200, 'le altre sessioni restano valide');
  assert.equal((await call('GET', '/me')).status, 401);
});

test('limite dei tentativi di accesso', async () => {
  const { call, advance } = setup();
  await registered(call, 'luca');
  for (let i = 0; i < 10; i++) {
    assert.equal((await call('POST', '/auth/login', { body: { username: 'luca', password: 'sbagliata!' } })).status, 401);
  }
  const blocked = await call('POST', '/auth/login', { body: { username: 'luca', password: 'password-bcw' } });
  assert.equal(blocked.status, 429);
  advance(16 * 60 * 1000);
  assert.equal((await call('POST', '/auth/login', { body: { username: 'luca', password: 'password-bcw' } })).status, 200);
});

test('registrazione chiusa', async () => {
  const { call } = setup({ env: { ALLOW_REGISTRATION: 'false' } });
  const r = await call('POST', '/auth/register', { body: { username: 'nuovo', password: 'password-bcw' } });
  assert.equal(r.status, 403);
  assert.equal(r.data.error, 'registration_closed');
});

test('sessione scaduta', async () => {
  const { call, advance } = setup();
  const token = await registered(call);
  advance(100 * 24 * 60 * 60 * 1000);
  assert.equal((await call('GET', '/me', { token })).status, 200, 'l\'uso allunga la sessione');
  advance(179 * 24 * 60 * 60 * 1000);
  assert.equal((await call('GET', '/me', { token })).status, 200);
  advance(181 * 24 * 60 * 60 * 1000);
  assert.equal((await call('GET', '/me', { token })).status, 401);
});

test('abbinamento degli account Classeviva', async () => {
  const { call, db } = setup();
  const token = await registered(call);

  const bad = await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'no' } });
  assert.equal(bad.status, 422);
  assert.equal(bad.data.error, 'classeviva_wrong_credentials');

  const added = await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } });
  assert.equal(added.status, 201);
  assert.equal(added.data.account.ident, 'S1234567X');
  assert.equal(added.data.account.name, 'Mario Rossi');
  assert.deepEqual(added.data.account.credentials, { username: 'mario.rossi', password: 'segreta1', ident: 'S1234567X' });

  // Le credenziali nel database sono cifrate.
  const stored = await db.prepare('SELECT credentials FROM accounts').first();
  assert.match(stored.credentials, /^v1:/);
  assert.ok(!stored.credentials.includes('segreta1'));

  // Stesso profilo: si aggiornano le credenziali, non si duplica.
  people['mario.rossi'].password = 'nuova-pass';
  const again = await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'nuova-pass' } });
  assert.equal(again.status, 200);
  assert.equal(again.data.created, false);
  people['mario.rossi'].password = 'segreta1';

  // Genitore con più figli: serve la scelta del profilo.
  const parent = await call('POST', '/accounts', { token, body: { username: 'genitore', password: 'segreta3' } });
  assert.equal(parent.status, 409);
  assert.equal(parent.data.error, 'needs_profile_choice');
  assert.equal(parent.data.choices.length, 2);
  const child = await call('POST', '/accounts', { token, body: { username: 'genitore', password: 'segreta3', ident: 'G2222222B' } });
  assert.equal(child.status, 201);
  assert.equal(child.data.account.ident, 'G2222222B');

  const list = await call('GET', '/accounts', { token });
  assert.deepEqual(list.data.accounts.map((a) => a.ident), ['S1234567X', 'G2222222B']);
  assert.equal(list.data.accounts[0].credentials.password, 'nuova-pass');

  const patched = await call('PATCH', `/accounts/${child.data.account.id}`, { token, body: { name: 'Sara Verdi', school: 'Liceo Galilei' } });
  assert.equal(patched.data.account.school, 'Liceo Galilei');

  // Un altro utente non vede né tocca gli account altrui.
  const other = await registered(call, 'altro');
  assert.equal((await call('GET', '/accounts', { token: other })).data.accounts.length, 0);
  assert.equal((await call('DELETE', `/accounts/${child.data.account.id}`, { token: other })).status, 404);
  assert.equal((await call('GET', `/sync/timetable/${child.data.account.id}`, { token: other })).status, 404);

  assert.equal((await call('DELETE', `/accounts/${child.data.account.id}`, { token })).status, 200);
  assert.equal((await call('GET', '/accounts', { token })).data.accounts.length, 1);
});

test('credenziali legate alla riga e alla chiave', async () => {
  const { call, db } = setup();
  const token = await registered(call);
  await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } });
  const other = await registered(call, 'altro');
  await call('POST', '/accounts', { token: other, body: { username: 'anna.bianchi', password: 'segreta2' } });
  // Copiando le credenziali cifrate su un'altra riga non si decifrano più.
  const row = await db.prepare("SELECT credentials FROM accounts WHERE ident = 'S1234567X'").first();
  await db.prepare("UPDATE accounts SET credentials = ? WHERE ident = 'S7654321Y'").bind(row.credentials).run();
  const list = await call('GET', '/accounts', { token: other });
  assert.equal(list.data.accounts[0].credentials, null);
});

test('scollegamento dal lato Classeviva', async () => {
  const { call } = setup();
  const a = await registered(call, 'primo');
  const b = await registered(call, 'secondo');
  await call('POST', '/accounts', { token: a, body: { username: 'mario.rossi', password: 'segreta1' } });
  await call('POST', '/accounts', { token: b, body: { username: 'mario.rossi', password: 'segreta1' } });
  await call('POST', '/accounts', { token: b, body: { username: 'anna.bianchi', password: 'segreta2' } });

  const headers = { 'X-Classeviva-Ident': 'S1234567X', 'X-Classeviva-Token': 'tok-S1234567X' };
  const forged = await call('GET', '/classeviva/links', { headers: { ...headers, 'X-Classeviva-Token': 'tok-S7654321Y' } });
  assert.equal(forged.status, 401);

  const links = await call('GET', '/classeviva/links', { headers });
  assert.equal(links.status, 200);
  assert.deepEqual(links.data.links.map((l) => l.username), ['primo', 'secondo']);

  assert.equal((await call('DELETE', `/classeviva/links/${links.data.links[0].id}`, { headers })).status, 200);
  assert.equal((await call('GET', '/accounts', { token: a })).data.accounts.length, 0);

  // Il token di Anna non può scollegare Mario.
  const anna = { 'X-Classeviva-Ident': 'S7654321Y', 'X-Classeviva-Token': 'tok-S7654321Y' };
  assert.equal((await call('DELETE', `/classeviva/links/${links.data.links[1].id}`, { headers: anna })).status, 404);

  const all = await call('DELETE', '/classeviva/links', { headers });
  assert.equal(all.data.removed, 1);
  assert.deepEqual((await call('GET', '/accounts', { token: b })).data.accounts.map((x) => x.ident), ['S7654321Y']);
});

test('sincronizzazione delle impostazioni con versioni', async () => {
  const { call } = setup();
  const token = await registered(call);
  const empty = await call('GET', '/sync/settings', { token });
  assert.deepEqual(empty.data, { data: null, version: 0, updatedAt: null });

  const first = await call('PUT', '/sync/settings', { token, body: { data: { accentColor: '#2f6db5' }, baseVersion: 0 } });
  assert.equal(first.status, 200);
  assert.equal(first.data.version, 1);

  // Un secondo dispositivo con una versione vecchia riceve il documento attuale.
  const stale = await call('PUT', '/sync/settings', { token, body: { data: { accentColor: '#000000' }, baseVersion: 0 } });
  assert.equal(stale.status, 409);
  assert.equal(stale.data.error, 'conflict');
  assert.equal(stale.data.version, 1);
  assert.deepEqual(stale.data.data, { accentColor: '#2f6db5' });

  const second = await call('PUT', '/sync/settings', { token, body: { data: { accentColor: '#000000' }, baseVersion: 1 } });
  assert.equal(second.data.version, 2);
  const read = await call('GET', '/sync/settings', { token });
  assert.deepEqual(read.data.data, { accentColor: '#000000' });
  assert.equal(read.data.version, 2);

  assert.equal((await call('PUT', '/sync/settings', { token, body: { data: [1, 2], baseVersion: 2 } })).status, 400);
  const huge = { text: 'x'.repeat(200 * 1024) };
  assert.equal((await call('PUT', '/sync/settings', { token, body: { data: huge, baseVersion: 2 } })).status, 413);
});

test('orario e file allegati', async () => {
  const { call, advance } = setup();
  const token = await registered(call);
  const account = (await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } })).data.account;

  const big = new Uint8Array(2_500_000).map((_, i) => i % 251);
  const put = await call('PUT', `/files/${account.id}/AAAA.jpg`, { token, raw: big, headers: { 'Content-Type': 'image/jpeg' } });
  assert.equal(put.status, 201);
  assert.equal(put.data.size, big.length);
  const small = new TextEncoder().encode('ciao');
  await call('PUT', `/files/${account.id}/BBBB.txt`, { token, raw: small, headers: { 'Content-Type': 'text/plain' } });

  const got = await call('GET', `/files/${account.id}/AAAA.jpg`, { token });
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('Content-Type'), 'image/jpeg');
  assert.deepEqual(got.data, big);

  const list = await call('GET', `/files/${account.id}`, { token });
  assert.deepEqual(list.data.files.map((f) => f.name), ['AAAA.jpg', 'BBBB.txt']);
  assert.equal(list.data.used, big.length + 4);

  assert.equal((await call('PUT', `/files/${account.id}/..%2Fx`, { token, raw: small })).status, 400);
  assert.equal((await call('PUT', `/files/${account.id}/.nascosto`, { token, raw: small })).status, 400);

  const timetable = {
    alignment: 'automatic',
    entries: [{ id: 'E1', title: 'Matematica', weekday: 1, start: 480, end: 540, attachments: [{ storedName: 'AAAA.jpg' }] }],
    occurrences: {},
  };
  const saved = await call('PUT', `/sync/timetable/${account.id}`, { token, body: { data: timetable, baseVersion: 0 } });
  assert.equal(saved.data.version, 1);
  // I file appena caricati restano anche se l'orario non li cita ancora.
  assert.equal((await call('GET', `/files/${account.id}`, { token })).data.files.length, 2);
  advance(11 * 60 * 1000);
  await call('PUT', `/sync/timetable/${account.id}`, { token, body: { data: timetable, baseVersion: 1 } });
  assert.deepEqual((await call('GET', `/files/${account.id}`, { token })).data.files.map((f) => f.name), ['AAAA.jpg']);

  const read = await call('GET', `/sync/timetable/${account.id}`, { token });
  assert.equal(read.data.version, 2);
  assert.equal(read.data.data.entries[0].title, 'Matematica');

  assert.equal((await call('DELETE', `/files/${account.id}/AAAA.jpg`, { token })).status, 200);
  assert.equal((await call('GET', `/files/${account.id}/AAAA.jpg`, { token })).status, 404);

  // Scollegando l'account se ne vanno anche orario e file.
  await call('PUT', `/files/${account.id}/CCCC.txt`, { token, raw: small });
  await call('DELETE', `/accounts/${account.id}`, { token });
  const again = (await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } })).data.account;
  assert.deepEqual((await call('GET', `/sync/timetable/${again.id}`, { token })).data, { data: null, version: 0, updatedAt: null });
  assert.equal((await call('GET', `/files/${again.id}`, { token })).data.used, 0);
});

test('limiti dei file', async () => {
  const { call } = setup({ env: { FILE_MAX_MB: '1', FILE_QUOTA_MB: '1.5' } });
  const token = await registered(call);
  const account = (await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } })).data.account;
  const tooBig = await call('PUT', `/files/${account.id}/a.bin`, { token, raw: new Uint8Array(1024 * 1024 + 1) });
  assert.equal(tooBig.status, 413);
  assert.equal(tooBig.data.error, 'too_large');
  assert.equal((await call('PUT', `/files/${account.id}/a.bin`, { token, raw: new Uint8Array(1024 * 1024) })).status, 201);
  const over = await call('PUT', `/files/${account.id}/b.bin`, { token, raw: new Uint8Array(600 * 1024) });
  assert.equal(over.data.error, 'quota_exceeded');
  // Sostituire un file conta solo la differenza.
  assert.equal((await call('PUT', `/files/${account.id}/a.bin`, { token, raw: new Uint8Array(1024 * 1024) })).status, 200);
});

test('cambio della password ed eliminazione dell\'account', async () => {
  const { call, db } = setup();
  const token = await registered(call);
  const second = (await call('POST', '/auth/login', { body: { username: 'giulia', password: 'password-bcw' } })).data.token;
  await call('POST', '/accounts', { token, body: { username: 'mario.rossi', password: 'segreta1' } });
  await call('PUT', '/sync/settings', { token, body: { data: { a: 1 }, baseVersion: 0 } });

  assert.equal((await call('PUT', '/me/password', { token, body: { currentPassword: 'no', newPassword: 'nuova-password' } })).status, 403);
  const changed = await call('PUT', '/me/password', { token, body: { currentPassword: 'password-bcw', newPassword: 'nuova-password' } });
  assert.equal(changed.status, 200);
  assert.equal((await call('GET', '/me', { token: second })).status, 401, 'le altre sessioni vengono chiuse');
  assert.equal((await call('GET', '/me', { token: changed.data.token })).status, 200);
  assert.equal((await call('POST', '/auth/login', { body: { username: 'giulia', password: 'nuova-password' } })).status, 200);

  assert.equal((await call('DELETE', '/me', { token: changed.data.token, body: { password: 'sbagliata' } })).status, 403);
  assert.equal((await call('DELETE', '/me', { token: changed.data.token, body: { password: 'nuova-password' } })).status, 200);
  for (const table of ['users', 'sessions', 'accounts', 'settings', 'timetables', 'files', 'file_chunks']) {
    assert.equal((await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first()).n, 0, table);
  }
});

test('proxy verso Classeviva e CORS', async () => {
  const { call, calls } = setup({ env: { ALLOWED_ORIGINS: 'https://kubos5.github.io' } });
  const ping = await call('GET', '/ping', { headers: { Origin: 'https://kubos5.github.io' } });
  assert.equal(ping.headers.get('X-BCW-Proxy'), '1');
  assert.equal(ping.headers.get('Access-Control-Allow-Origin'), 'https://kubos5.github.io');
  const forwarded = await call('GET', '/v1/students/123/grades', { headers: { 'Z-Auth-Token': 'tok' } });
  assert.equal(forwarded.data.path, '/rest/v1/students/123/grades');
  assert.equal(calls.at(-1), 'https://web.spaggiari.eu/rest/v1/students/123/grades');
  const archive = await call('POST', '/archive/24/students/1/documents', { raw: '{}' });
  assert.equal(archive.data.method, 'POST');
  assert.equal(calls.at(-1), 'https://web24.spaggiari.eu/rest/v1/students/1/documents');

  const foreign = await call('GET', '/', { headers: { Origin: 'https://altro.example' } });
  assert.equal(foreign.headers.get('Access-Control-Allow-Origin'), null);
  const preflight = await call('OPTIONS', '/accounts', { headers: { Origin: 'https://kubos5.github.io' } });
  assert.equal(preflight.status, 204);
  assert.match(preflight.headers.get('Access-Control-Allow-Headers'), /Authorization/);
});

test('percorso di base e percorsi sconosciuti', async () => {
  const { call } = setup({ env: { BASE_PATH: '/bcw' } });
  assert.equal((await call('GET', '/bcw/')).data.name, 'BCW API');
  assert.equal((await call('GET', '/bcw/ping')).headers.get('X-BCW-Proxy'), '1');
  assert.equal((await call('GET', '/bcw/nulla')).status, 404);
  assert.equal((await call('PUT', '/bcw/accounts')).status, 405);
});

test('file citati da un orario', () => {
  const names = referencedFiles({
    entries: [{ attachments: [{ storedName: 'a.jpg' }] }, { attachments: null }, null],
    occurrences: { 'x@2026-10-01': { attachments: [{ storedName: 'b.pdf' }, { name: 'senza' }] } },
  });
  assert.deepEqual([...names].sort(), ['a.jpg', 'b.pdf']);
});
