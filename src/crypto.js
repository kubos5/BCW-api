// Password, token di sessione e cifratura delle credenziali Classeviva (Web Crypto,
// disponibile sia nei Cloudflare Workers sia in Node).

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** I Workers non accettano più di 100.000 iterazioni di PBKDF2. */
export const DEFAULT_ITERATIONS = 100_000;

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const toBase64URL = (bytes) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
export const uuid = () => crypto.randomUUID().toUpperCase();

/** Token di sessione: 32 byte casuali in base64url. */
export const newToken = () => toBase64URL(randomBytes(32));

export async function sha256Hex(text) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))));
}

/** Confronto a tempo costante tra due stringhe della stessa lunghezza. */
function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// MARK: - Password

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

/** "pbkdf2-sha256$<iterazioni>$<sale>$<hash>" (base64). */
export async function hashPassword(password, iterations = DEFAULT_ITERATIONS) {
  const salt = randomBytes(16);
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2-sha256$${iterations}$${toBase64(salt)}$${toBase64(hash)}`;
}

/** `{ valid, iterations }`: le iterazioni servono a capire se l'hash va rifatto. */
export async function verifyPassword(password, stored) {
  const [scheme, iter, salt, hash] = String(stored).split('$');
  const iterations = Number(iter);
  if (scheme !== 'pbkdf2-sha256' || !Number.isInteger(iterations) || iterations < 1 || !salt || !hash) {
    return { valid: false, iterations: 0 };
  }
  const computed = await pbkdf2(password, fromBase64(salt), iterations);
  return { valid: equal(toBase64(computed), hash), iterations };
}

// MARK: - Credenziali Classeviva

const keyCache = new Map();

async function credentialsKey(secret) {
  if (!secret) throw new Error('Manca CREDENTIALS_KEY: imposta il segreto con 32 byte in base64.');
  if (!keyCache.has(secret)) {
    let raw;
    try {
      raw = fromBase64(secret.trim());
    } catch {
      raw = null;
    }
    if (!raw || raw.length !== 32) throw new Error('CREDENTIALS_KEY deve essere di 32 byte in base64 (openssl rand -base64 32).');
    keyCache.set(secret, crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']));
  }
  return keyCache.get(secret);
}

/**
 * Cifra un oggetto con AES-256-GCM. `context` (es. "utente:ident") è legato al testo
 * cifrato: copiato in un'altra riga, non si decifra più.
 */
export async function seal(value, secret, context) {
  const key = await credentialsKey(secret);
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(context) }, key, encoder.encode(JSON.stringify(value)),
  );
  const out = new Uint8Array(12 + data.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(data), 12);
  return `v1:${toBase64(out)}`;
}

export async function open(sealed, secret, context) {
  const [version, payload] = String(sealed).split(':');
  if (version !== 'v1' || !payload) throw new Error('Formato delle credenziali sconosciuto.');
  const key = await credentialsKey(secret);
  const bytes = fromBase64(payload);
  const data = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.subarray(0, 12), additionalData: encoder.encode(context) }, key, bytes.subarray(12),
  );
  return JSON.parse(decoder.decode(data));
}
