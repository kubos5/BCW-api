#!/usr/bin/env node
// BCW-api con Node e SQLite, senza Cloudflare: per le prove in locale o per un server proprio.
//
//   CREDENTIALS_KEY=$(openssl rand -base64 32) node server/node.js
//
// Variabili: PORT (8787), HOST (0.0.0.0), DATABASE (bcw.sqlite), più le stesse del Worker
// (CREDENTIALS_KEY, ALLOWED_ORIGINS, ALLOW_REGISTRATION, FILE_MAX_MB, FILE_QUOTA_MB…).
// Serve Node 22.5 o successivo (`node:sqlite`).

import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.js';
import { SQLiteD1 } from './sqlite.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PORT = Number(process.env.PORT) || 8787;
const HOST = process.env.HOST || '0.0.0.0';

const db = new SQLiteD1(process.env.DATABASE || 'bcw.sqlite');
db.migrate(`${ROOT}migrations`);

const env = { ...process.env, DB: db };
if (!env.CREDENTIALS_KEY) {
  console.error('Manca CREDENTIALS_KEY. Generala con: openssl rand -base64 32');
  process.exit(1);
}
const handle = createApp();

const server = createServer(async (req, res) => {
  try {
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (Array.isArray(value)) value.forEach((v) => headers.append(name, v));
      else if (value != null) headers.set(name, value);
    }
    if (!headers.has('CF-Connecting-IP')) headers.set('CF-Connecting-IP', req.socket.remoteAddress ?? 'local');
    const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
    const request = new Request(`http://${req.headers.host ?? 'localhost'}${req.url}`, {
      method: req.method,
      headers,
      body: hasBody ? Readable.toWeb(req) : undefined,
      duplex: 'half',
    });
    const response = await handle(request, env);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body && req.method !== 'HEAD') {
      for await (const chunk of response.body) res.write(chunk);
    }
    res.end();
  } catch (error) {
    console.error(error);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end('{"error":"server_error"}');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`BCW API su http://localhost:${PORT}`);
});
