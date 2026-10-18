# CLAUDE.md — BCW API

Backend di BCW (Better ClasseViVa): app iOS in https://github.com/kubos5/BCW, versione web in
https://github.com/kubos5/BCW-web. Rispondi all'utente in **italiano**. Messaggi dell'API e commenti in italiano.

- Cloudflare Worker (`src/worker.js`, `wrangler.toml`) con database D1 (`env.DB`, migrazioni in `migrations/`).
  `src/app.js` non dipende dalla piattaforma: `createApp({ fetch, now })` restituisce `handle(request, env)`;
  `fetch` è quello verso Classeviva (finto nelle prove), `now` l'orologio.
- Node: `server/node.js` (server HTTP) e `server/sqlite.js` (stessa interfaccia di D1 sopra `node:sqlite`, con
  `batch` in transazione e le chiavi esterne accese). Serve Node 22.5+. `npm test` usa SQLite in memoria e un
  Classeviva finto (`test/api.test.js`); `npm start` avvia il server Node (vuole `CREDENTIALS_KEY`).
- Nessuna dipendenza a runtime; `wrangler` solo per sviluppo e pubblicazione. `npx wrangler deploy --dry-run`
  controlla che il Worker si impacchetti; `npm run dev` lo prova con workerd e un D1 locale (`.dev.vars`).
- Account BCW: nome utente minuscolo, password PBKDF2-SHA256 (massimo 100.000 iterazioni: limite dei Workers),
  sessioni con token casuale di cui si salva solo lo SHA-256. Limite dei tentativi nella tabella `attempts`.
- Account Classeviva abbinati (`accounts`): il server verifica le credenziali accedendo a Classeviva e le salva
  cifrate con AES-GCM (`CREDENTIALS_KEY`, contesto `utente:ident`); `GET /accounts` le restituisce in chiaro alle
  app, che accedono a Classeviva da sé. Unico per `(user_id, ident)`.
- Lato Classeviva (`/classeviva/links`): l'identità si prova con `X-Classeviva-Ident` + `X-Classeviva-Token`, che il
  server verifica chiedendo `students/{id}/card` a Classeviva.
- Sincronizzazione: `settings` (per utente) e `timetables` (per account abbinato) con versione; `PUT` con
  `baseVersion`, `409 conflict` con il documento attuale. File dell'orario in `files` + `file_chunks` (pezzi da
  1 MB, una riga di D1 non supera 2 MB), quota per utente; i file non citati dall'orario si cancellano al
  salvataggio dell'orario dopo 10 minuti di grazia.
- Scollegare un account cancella orario e file (`accountDeletion`): cancellazioni esplicite in un `batch`, oltre
  alle chiavi esterne.
- D1: al massimo 50 query per richiesta sul piano gratuito (anche quelle di un `batch`), 100 parametri per query;
  i BLOB tornano come array di numeri (`toBytes`).
- Errori: `HttpError(status, codice, messaggio)` → `{ error, message, ... }`. Le app mostrano `message`.
- Il Worker fa anche da proxy per Classeviva come `proxy/cloudflare-worker.js` di BCW-web (`/v1`, `/archive/<aa>`,
  `/ping`): tenere i due allineati.
- README: niente trattini lunghi, niente grassetto/corsivo, tabelle solo se indispensabili.
