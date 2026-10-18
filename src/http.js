// Risposte JSON, errori e CORS.

/** Errore con codice HTTP e codice leggibile dalle app (`error`), più un messaggio in italiano. */
export class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const badRequest = (message = 'Richiesta non valida.', extra) => new HttpError(400, 'invalid_request', message, extra);
export const unauthorized = (message = 'Sessione scaduta: accedi di nuovo.') => new HttpError(401, 'unauthorized', message);
export const notFound = (message = 'Elemento non trovato.') => new HttpError(404, 'not_found', message);

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

export function errorResponse(error) {
  if (error instanceof HttpError) {
    return json({ error: error.code, message: error.message, ...error.extra }, error.status);
  }
  console.error(error);
  return json({ error: 'server_error', message: 'Errore interno del server BCW.' }, 500);
}

/** Corpo JSON della richiesta (un oggetto), con un limite di dimensione. */
export async function readJSON(request, limit = 256 * 1024) {
  const text = await readText(request, limit);
  if (!text) return {};
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw badRequest('Il corpo della richiesta non è JSON valido.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw badRequest();
  return value;
}

export async function readText(request, limit) {
  const bytes = await readBytes(request, limit);
  return new TextDecoder().decode(bytes);
}

/** Legge il corpo fermandosi appena supera `limit` byte. */
export async function readBytes(request, limit) {
  const declared = Number(request.headers.get('Content-Length'));
  if (Number.isFinite(declared) && declared > limit) throw tooLarge(limit);
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      throw tooLarge(limit);
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function tooLarge(limit) {
  const mb = limit >= 1024 * 1024 ? `${Math.round((limit / (1024 * 1024)) * 10) / 10} MB` : `${Math.round(limit / 1024)} KB`;
  return new HttpError(413, 'too_large', `Dati troppo grandi (massimo ${mb}).`);
}

// MARK: - CORS

const ALLOWED_HEADERS = [
  'Authorization', 'Content-Type', 'If-Match', 'X-BCW-Client',
  'X-Classeviva-Token', 'X-Classeviva-Ident', 'Z-Auth-Token', 'Z-Dev-Apikey',
].join(', ');

/**
 * Intestazioni CORS per l'origine della richiesta. L'API usa token nell'intestazione
 * `Authorization` (niente cookie), quindi di base accetta qualsiasi sito; con
 * `ALLOWED_ORIGINS` (separate da virgole) si limita ad alcuni.
 */
export function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return {};
  const allowed = String(env.ALLOWED_ORIGINS || '*').split(',').map((s) => s.trim()).filter(Boolean);
  if (!(allowed.includes('*') || allowed.includes(origin))) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': ALLOWED_HEADERS,
    'Access-Control-Expose-Headers': 'Content-Disposition, X-BCW-Proxy, X-BCW-API',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

export function withHeaders(response, headers) {
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(headers)) out.headers.set(name, value);
  return out;
}
