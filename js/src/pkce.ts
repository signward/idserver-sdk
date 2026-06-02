/**
 * PKCE (Proof Key for Code Exchange) helpers built on the Web Crypto API.
 * Works in Node 18+ and all modern browsers.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]!);
  }
  const b64 = typeof btoa !== 'undefined'
    ? btoa(str)
    : Buffer.from(bytes).toString('base64');
  return b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Generate a high-entropy PKCE code verifier (RFC 7636).
 * The verifier is a URL-safe string between 43 and 128 characters.
 */
export function generateCodeVerifier(length: number = 64): string {
  if (length < 43 || length > 128) {
    throw new RangeError('PKCE code verifier length must be between 43 and 128');
  }
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ALPHABET[randomBytes[i]! % ALPHABET.length];
  }
  return out;
}

/**
 * Derive the S256 code challenge from a verifier.
 */
export async function deriveCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}

/**
 * Convenience: generate a verifier + challenge pair.
 */
export async function generatePkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateCodeVerifier();
  const challenge = await deriveCodeChallenge(verifier);
  return { verifier, challenge };
}
