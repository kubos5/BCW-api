# BCW API

Il backend di [BCW](https://github.com/kubos5/BCW) (Better ClasseViVa), il client per il registro elettronico Classeviva per [iPhone e iPad](https://github.com/kubos5/BCW) e per il [web](https://github.com/kubos5/BCW-web).

Con un account BCW si possono:

- abbinare uno o più account Classeviva (ad esempio quelli di fratelli e sorelle, o i profili di un genitore) ed entrare in tutti con un solo accesso, su qualsiasi dispositivo
- sincronizzare impostazioni e aspetto dell'app
- sincronizzare l'orario di ogni account Classeviva abbinato, con i file e le foto allegati

Chi entra con un account Classeviva vede a quali account BCW è abbinato e può scollegarsi da ognuno, senza conoscerne la password.

È un Cloudflare Worker con un database D1: il piano gratuito di Cloudflare basta. Lo stesso codice gira anche con Node e SQLite, per le prove in locale o su un server proprio.

> BCW non è affiliato a Gruppo Spaggiari Parma S.p.A.

---

## Come funziona

- Account BCW: nome utente (da 3 a 32 caratteri tra lettere minuscole, cifre, punto, trattino e trattino basso) e password di almeno 8 caratteri. La password è salvata come hash PBKDF2-SHA256 con sale casuale. Dopo 10 tentativi sbagliati in 15 minuti l'accesso a quell'account si blocca per il resto della finestra.
- Sessioni: l'app riceve un token casuale da inviare come `Authorization: Bearer <token>`. Il server ne salva solo l'hash SHA-256. Una sessione scade dopo 180 giorni senza uso; cambiando password si esce da tutti gli altri dispositivi.
- Account Classeviva abbinati: abbinando un account il server accede a Classeviva per verificare le credenziali e ricavare profilo e nome. Nome utente e password di Classeviva sono cifrati con AES-256-GCM e la chiave segreta `CREDENTIALS_KEY`, legati all'account BCW e al profilo (copiati in un'altra riga non si decifrano più). Entrando con l'account BCW l'app riceve le credenziali e accede a Classeviva da sé, come con un account salvato sul dispositivo.
- Lato Classeviva: con il token di una sessione Classeviva (intestazioni `X-Classeviva-Ident` e `X-Classeviva-Token`) il server chiede a Classeviva la scheda di quel profilo; se risponde, il profilo è confermato e si possono vedere e togliere i suoi abbinamenti. La password non serve.
- Sincronizzazione: impostazioni e orario sono documenti JSON con un numero di versione. L'app invia la versione da cui è partita; se nel frattempo un altro dispositivo ha salvato, il server risponde `409` con il documento attuale e l'app unisce le modifiche.
- File dell'orario: divisi in pezzi da 1 MB (una riga di D1 non supera i 2 MB). Di base al massimo 10 MB per file e 100 MB per account BCW. I file che l'orario non cita più vengono cancellati quando l'orario viene salvato (non quelli caricati negli ultimi 10 minuti, che l'orario potrebbe non citare ancora).
- Proxy: il Worker risponde anche come il proxy di BCW-web (`/v1/…`, `/archive/<aa>/…`, `/ping`), quindi la versione web può usarlo sia per l'account BCW sia per raggiungere Classeviva.

Scollegando un account Classeviva (dall'account BCW o dal lato Classeviva) si cancellano anche il suo orario e i suoi file sul server. Eliminando l'account BCW si cancella tutto.

---

## Pubblicazione su Cloudflare

Serve [Node.js](https://nodejs.org) 22 o successivo e un account Cloudflare (gratuito).

```
git clone https://github.com/kubos5/BCW-api
cd BCW-api
npm install
npx wrangler login
```

1. Crea il database e copia l'id stampato in `wrangler.toml`, al posto di `database_id`:

   ```
   npx wrangler d1 create bcw
   ```

2. Crea le tabelle:

   ```
   npm run db:migrate
   ```

3. Genera la chiave che cifra le credenziali di Classeviva e salvala come segreto del Worker:

   ```
   openssl rand -base64 32
   npx wrangler secret put CREDENTIALS_KEY
   ```

   Conserva una copia della chiave in un posto sicuro: senza, le credenziali salvate non si possono più leggere e gli account Classeviva vanno abbinati di nuovo (impostazioni e orario restano).

4. Pubblica il Worker:

   ```
   npm run deploy
   ```

   L'indirizzo è del tipo `https://bcw-api.tuonome.workers.dev`. Aprendolo nel browser deve rispondere `{"name":"BCW API",…}`.

5. Collega le app:
   - web: in `config.json` di BCW-web scrivi l'indirizzo in `api` (e, se vuoi usare questo Worker anche come proxy per Classeviva, in `proxy`); ognuno può cambiarlo da Impostazioni › Account › Server BCW
   - iPhone e iPad: l'indirizzo predefinito è in `BCWServer.defaultURL` (`BCW/Networking/BCWClient.swift`); anche lì si cambia da Impostazioni › Account › Server BCW

Quando il codice cambia: `npm run deploy`; se in `migrations/` c'è un file nuovo, prima `npm run db:migrate`.

### Variabili

In `wrangler.toml`, sezione `[vars]`, oppure nel pannello di Cloudflare (Workers › bcw-api › Impostazioni › Variabili e segreti):

- `CREDENTIALS_KEY` (segreto, obbligatorio): 32 byte in base64
- `ALLOWED_ORIGINS`: siti che possono usare l'API dal browser, separati da virgole, oppure `*` per tutti (predefinito). L'API non usa cookie, quindi `*` è sicuro; puoi limitarlo ad esempio a `https://kubos5.github.io`
- `ALLOW_REGISTRATION`: `false` per non accettare nuovi account BCW
- `FILE_MAX_MB` e `FILE_QUOTA_MB`: dimensione massima di un file dell'orario e spazio per account BCW, in MB (predefiniti 10 e 100)
- `PASSWORD_ITERATIONS`: iterazioni di PBKDF2 per le password BCW, da 10.000 a 100.000 (predefinito 100.000, il massimo che i Workers accettano). Gli hash si aggiornano da soli al primo accesso
- `BASE_PATH`: percorso sotto cui è pubblicata l'API, se non è la radice (es. `/bcw`)

### Limiti del piano gratuito

Il piano gratuito di Workers e D1 permette 100.000 richieste e 100.000 scritture al giorno e 5 GB di dati, abbondanti per un uso personale o per una classe. Se un giorno l'hash delle password supera il tempo di CPU del piano gratuito (gli accessi falliscono con un errore 1102), abbassa `PASSWORD_ITERATIONS`.

---

## Prove in locale

Con Node e SQLite, senza Cloudflare (serve Node 22.5 o successivo):

```
CREDENTIALS_KEY=$(openssl rand -base64 32) npm start
```

L'API risponde su http://localhost:8787 e i dati stanno in `bcw.sqlite` (variabili `PORT`, `HOST`, `DATABASE`, più quelle del Worker). Per provarla con BCW-web avviato con `node server.js`, scrivi `http://localhost:8787` in Impostazioni › Account › Server BCW.

Oppure con il runtime vero dei Workers e un D1 locale:

```
echo "CREDENTIALS_KEY=$(openssl rand -base64 32)" > .dev.vars
npm run db:migrate:local
npm run dev
```

Le prove automatiche usano SQLite in memoria e un Classeviva finto:

```
npm test
```

---

## API

Tutte le risposte sono JSON. Gli errori hanno la forma `{ "error": "codice", "message": "testo da mostrare" }`; i codici principali sono `invalid_request`, `unauthorized`, `invalid_credentials`, `username_taken`, `too_many_attempts`, `registration_closed`, `not_found`, `conflict`, `limit_reached`, `too_large`, `quota_exceeded`, `needs_profile_choice`, `classeviva_wrong_credentials`, `classeviva_unauthorized`, `classeviva_unavailable`.

Le richieste segnate con (sessione) vogliono `Authorization: Bearer <token>`. Le date sono millisecondi dall'epoca Unix.

### Account BCW

- `GET /`: nome, versione, se la registrazione è aperta e limiti dei file
- `POST /auth/register` `{ username, password, client? }` → `201 { token, user }`
- `POST /auth/login` `{ username, password, client? }` → `{ token, user }`
- `POST /auth/logout` (sessione): chiude la sessione
- `GET /me` (sessione) → `{ user, limits }`
- `PUT /me/password` (sessione) `{ currentPassword, newPassword }` → `{ token, user }`: nuova sessione, le altre vengono chiuse
- `DELETE /me` (sessione) `{ password }`: elimina l'account BCW e tutti i suoi dati

`user` è `{ id, username, createdAt }`. `client` è un nome facoltativo del dispositivo (anche nell'intestazione `X-BCW-Client`).

### Account Classeviva abbinati

- `GET /accounts` (sessione) → `{ accounts }`
- `POST /accounts` (sessione) `{ username, password, ident? }` → `201 { account, created: true }`, oppure `200` se il profilo era già abbinato (le credenziali vengono aggiornate). Per un genitore con più figli senza `ident` risponde `409 needs_profile_choice` con `choices: [{ ident, name, school }]`. Al massimo 10 account
- `PATCH /accounts/:id` (sessione) `{ name?, school?, position? }`: nome e scuola mostrati, ordine
- `DELETE /accounts/:id` (sessione): scollega l'account (con orario e file)

`account` è `{ id, ident, name, school, credentials: { username, password, ident }, position, createdAt, updatedAt }`.

### Lato Classeviva

Con le intestazioni `X-Classeviva-Ident` (es. `S1234567X`) e `X-Classeviva-Token` (il token di una sessione Classeviva di quel profilo):

- `GET /classeviva/links` → `{ ident, links: [{ id, username, linkedAt }] }`: gli account BCW a cui è abbinato il profilo
- `DELETE /classeviva/links/:id`: scollega il profilo da quell'account BCW
- `DELETE /classeviva/links` → `{ removed }`: scollega il profilo da tutti gli account BCW

### Sincronizzazione

- `GET /sync/settings` (sessione) → `{ data, version, updatedAt }` (`data: null, version: 0` se non c'è ancora)
- `PUT /sync/settings` (sessione) `{ data, baseVersion }` → `{ version, updatedAt }`, oppure `409 conflict` con `data`, `version` e `updatedAt` attuali
- `GET /sync/timetable/:accountId` e `PUT /sync/timetable/:accountId`: lo stesso per l'orario di un account abbinato (lo stesso JSON dell'app e del backup dell'orario, massimo 1 MB)

Le impostazioni sono massimo 128 KB. Le app sincronizzano solo le preferenze che valgono su tutti i dispositivi (voti, Dashboard, Orario, compiti fatti, Aspetto) e conservano le chiavi che non conoscono.

### File dell'orario

- `GET /files/:accountId` (sessione) → `{ files: [{ name, type, size, createdAt }], used, quota }`
- `PUT /files/:accountId/:name` (sessione), con il file come corpo e il suo `Content-Type`
- `GET /files/:accountId/:name` (sessione): il file
- `DELETE /files/:accountId/:name` (sessione)

`name` è lo `storedName` dell'allegato nell'orario (lettere, cifre, punto, trattino e trattino basso).

### Proxy per Classeviva

- `GET /ping` → `{"ok":true}` con l'intestazione `X-BCW-Proxy`
- `GET|POST /v1/<percorso>` → `https://web.spaggiari.eu/rest/v1/<percorso>`
- `GET|POST /archive/<aa>/<percorso>` → `https://web<aa>.spaggiari.eu/rest/v1/<percorso>`

---

## Struttura del codice

```
src/
├── worker.js       Punto d'ingresso del Cloudflare Worker
├── app.js          Instradamento e gestori: account, abbinamenti, sincronizzazione, file
├── classeviva.js   Accesso e verifica dei token su Classeviva, proxy per il web
├── crypto.js       Password, token di sessione, cifratura delle credenziali
└── http.js         Risposte JSON, errori, CORS, lettura del corpo con limite
migrations/         Schema del database (D1 / SQLite)
server/
├── node.js         Server Node con SQLite (prove in locale o server proprio)
└── sqlite.js       Adattatore con l'interfaccia di D1 sopra node:sqlite
test/               Prove con node:test
wrangler.toml       Configurazione del Worker
```

---

## Licenza

Distribuito con licenza MIT. Vedi [LICENSE](LICENSE).
