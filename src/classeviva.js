// Comunicazione con Classeviva: verifica delle credenziali e dei token, e proxy per la
// versione web (il browser non può chiamare direttamente `web.spaggiari.eu`).

import { HttpError, corsHeaders, json } from './http.js';

export const CLASSEVIVA_BASE = 'https://web.spaggiari.eu/rest/v1';

const CLASSEVIVA_HEADERS = {
  'User-Agent': 'CVVS/std/4.2.3 Android/12',
  'Z-Dev-Apikey': 'Tg1NWEwNGIgIC0K',
  Accept: 'application/json',
};

/** "S1234567X" → "1234567". */
export const studentId = (ident) => String(ident ?? '').replace(/\D/g, '');
export const normalizeIdent = (ident) => String(ident ?? '').trim().toUpperCase();

const unavailable = () => new HttpError(502, 'classeviva_unavailable', 'Impossibile contattare Classeviva. Riprova tra poco.');

function nameCased(text) {
  return String(text ?? '').toLowerCase().replace(/(^|[\s'-])(\p{L})/gu, (_, sep, letter) => sep + letter.toUpperCase()).trim();
}

/**
 * Accede a Classeviva con le credenziali. Restituisce `{ ident, name }`; lancia
 * `needs_profile_choice` (con `choices`) per gli account genitore con più figli e
 * `classeviva_wrong_credentials` se Classeviva rifiuta l'accesso.
 */
export async function classevivaLogin(fetchImpl, { username, password, ident }) {
  let response;
  try {
    response = await fetchImpl(`${CLASSEVIVA_BASE}/auth/login`, {
      method: 'POST',
      headers: { ...CLASSEVIVA_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ uid: username, pass: password, ident: ident || null }),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw unavailable();
  }
  let body = null;
  try { body = await response.json(); } catch { /* non è JSON */ }
  if ([400, 401, 422].includes(response.status)) {
    throw new HttpError(422, 'classeviva_wrong_credentials', 'Classeviva non ha accettato nome utente e password.');
  }
  if (!response.ok || !body || typeof body !== 'object') throw unavailable();
  if (!body.token && Array.isArray(body.choices) && body.choices.length) {
    const choices = body.choices
      .filter((c) => c && typeof c.ident === 'string')
      .map((c) => ({ ident: c.ident, name: String(c.name ?? ''), school: String(c.school ?? '') }));
    throw new HttpError(409, 'needs_profile_choice', 'Scegli il profilo da collegare.', { choices });
  }
  const resolvedIdent = normalizeIdent(body.ident || ident);
  if (!body.token || !studentId(resolvedIdent)) throw unavailable();
  const name = nameCased([body.firstName, body.lastName].filter(Boolean).join(' '));
  return { ident: resolvedIdent, name: name || null };
}

/**
 * Verifica che un token di Classeviva appartenga al profilo `ident`: la scheda dello
 * studente risponde solo al suo token. Serve a chi entra con un account Classeviva per
 * vedere (e scollegare) gli account BCW a cui è abbinato, senza inviare la password.
 */
export async function verifyClassevivaToken(fetchImpl, ident, token) {
  const id = studentId(ident);
  if (!id || !token) throw new HttpError(401, 'classeviva_unauthorized', 'Accedi di nuovo a Classeviva.');
  let response;
  try {
    response = await fetchImpl(`${CLASSEVIVA_BASE}/students/${id}/card`, {
      headers: { ...CLASSEVIVA_HEADERS, 'Z-Auth-Token': token },
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw unavailable();
  }
  if (response.status === 401 || response.status === 403 || response.status === 404) {
    throw new HttpError(401, 'classeviva_unauthorized', 'Classeviva non ha confermato l\'accesso: accedi di nuovo e riprova.');
  }
  if (!response.ok) throw unavailable();
  let body = null;
  try { body = await response.json(); } catch { /* ignorato */ }
  const card = body?.card ?? body?.cards?.[0];
  // Se la scheda indica un altro profilo dello stesso tipo (S studente, G genitore), il
  // token non è di questo profilo. Tra tipi diversi i codici possono non coincidere.
  const claimed = normalizeIdent(ident);
  const shown = normalizeIdent(card?.ident);
  if (shown && shown[0] === claimed[0] && studentId(shown) !== id) {
    throw new HttpError(401, 'classeviva_unauthorized', 'Il token di Classeviva appartiene a un altro profilo.');
  }
  return normalizeIdent(ident);
}

// MARK: - Proxy

function upstreamURL(pathname) {
  let m = /^(?:\/api)?\/v1(\/[^?#]*)$/.exec(pathname);
  if (m) return `${CLASSEVIVA_BASE}${m[1]}`;
  m = /^(?:\/api)?\/archive\/(\d{2})(\/[^?#]*)$/.exec(pathname);
  if (m) return `https://web${m[1]}.spaggiari.eu/rest/v1${m[2]}`;
  return null;
}

export const isProxyPath = (pathname) => upstreamURL(pathname) != null || /^(?:\/api)?\/ping$/.test(pathname);

/**
 * Inoltra la richiesta seguendo i reindirizzamenti (alcuni allegati della Bacheca vengono
 * serviti da un altro indirizzo). Il token va solo ai server di Classeviva.
 */
async function fetchUpstream(fetchImpl, url, { method, headers, body }) {
  let response = await fetchImpl(url, { method, headers, body, redirect: 'manual' });
  for (let hops = 0; hops < 5 && [301, 302, 303, 307, 308].includes(response.status); hops++) {
    const location = response.headers.get('Location');
    if (!location) break;
    const next = new URL(location, url);
    if (next.protocol !== 'https:') break;
    headers = { ...headers };
    if (!/(^|\.)spaggiari\.eu$/.test(next.hostname)) delete headers['Z-Auth-Token'];
    if (response.status !== 307 && response.status !== 308) {
      method = 'GET';
      body = undefined;
      delete headers['Content-Type'];
    }
    url = next.href;
    response = await fetchImpl(url, { method, headers, body, redirect: 'manual' });
  }
  return response;
}

/** Stesso comportamento di `proxy/cloudflare-worker.js` di BCW-web. */
export async function proxy(request, env, fetchImpl, pathname = new URL(request.url).pathname) {
  const cors = corsHeaders(request, env);
  if (/^(?:\/api)?\/ping$/.test(pathname)) {
    return new Response('{"ok":true}', {
      headers: { ...cors, 'Content-Type': 'application/json', 'X-BCW-Proxy': '1', 'X-BCW-API': '1', 'Cache-Control': 'no-store' },
    });
  }
  const failure = (status, message) => json({ message }, status, { ...cors, 'X-BCW-Proxy': '1' });
  if (request.method !== 'GET' && request.method !== 'POST') return failure(405, 'Metodo non consentito');
  const target = upstreamURL(pathname);
  if (!target) return failure(404, 'Percorso non valido');

  const headers = { ...CLASSEVIVA_HEADERS };
  const token = request.headers.get('Z-Auth-Token');
  if (token) headers['Z-Auth-Token'] = token;
  let body;
  if (request.method === 'POST') {
    body = await request.text();
    // Classeviva rifiuta il JSON vuoto `{}` ma accetta un corpo vuoto.
    if (body.replace(/\s/g, '') === '{}') body = '';
    headers['Content-Type'] = 'application/json';
  }
  try {
    const upstream = await fetchUpstream(fetchImpl, target, { method: request.method, headers, body });
    const out = new Headers({ ...cors, 'X-BCW-Proxy': '1', 'Cache-Control': 'no-store' });
    for (const name of ['Content-Type', 'Content-Disposition']) {
      const value = upstream.headers.get(name);
      if (value) out.set(name, value);
    }
    return new Response(upstream.body, { status: upstream.status, headers: out });
  } catch {
    return failure(502, 'Impossibile contattare Classeviva.');
  }
}
