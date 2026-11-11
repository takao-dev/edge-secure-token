import { toBase64Url, fromBase64Url, utf8Encode, utf8Decode, timingSafeEqual } from './base64url.js';

export type SupportedAlgorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'Ed25519';

export async function importSignKey(
  alg: SupportedAlgorithm,
  key: string | CryptoKey
): Promise<CryptoKey> {
  if (typeof key !== 'string') return key;

  const crypto = globalThis.crypto;
  if (alg.startsWith('HS')) {
    const hash = `SHA-${alg.slice(2)}`;
    return crypto.subtle.importKey(
      'raw',
      utf8Encode(key) as unknown as BufferSource,
      { name: 'HMAC', hash: { name: hash } },
      false,
      ['sign', 'verify']
    );
  }

  throw new Error(`String keys are supported for HMAC (HS256/384/512). For ${alg}, provide a CryptoKey.`);
}

export async function signData(
  alg: SupportedAlgorithm,
  key: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  const crypto = globalThis.crypto;
  let signature: ArrayBuffer;

  if (alg.startsWith('HS')) {
    signature = await crypto.subtle.sign('HMAC', key, data as unknown as BufferSource);
  } else if (alg.startsWith('ES')) {
    const hash = `SHA-${alg.slice(2)}`;
    signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: hash } },
      key,
      data as unknown as BufferSource
    );
  } else if (alg === 'Ed25519') {
    signature = await crypto.subtle.sign('Ed25519', key, data as unknown as BufferSource);
  } else {
    throw new Error(`Unsupported signing algorithm: ${alg}`);
  }

  return new Uint8Array(signature);
}

export async function verifyData(
  alg: SupportedAlgorithm,
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  const crypto = globalThis.crypto;

  if (alg.startsWith('HS')) {
    // For HMAC, compute expected signature and use constant-time comparison
    const expected = await signData(alg, key, data);
    return timingSafeEqual(expected, signature);
  }

  if (alg.startsWith('ES')) {
    const hash = `SHA-${alg.slice(2)}`;
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: hash } },
      key,
      signature as unknown as BufferSource,
      data as unknown as BufferSource
    );
  }

  if (alg === 'Ed25519') {
    return crypto.subtle.verify(
      'Ed25519',
      key,
      signature as unknown as BufferSource,
      data as unknown as BufferSource
    );
  }

  return false;
}

/**
 * Encrypt specific claims within a payload using AES-256-GCM.
 */
export async function encryptClaims(
  payload: Record<string, any>,
  claimsToEncrypt: string[],
  secret: string
): Promise<Record<string, any>> {
  const crypto = globalThis.crypto;
  const rawKey = utf8Encode(secret.padEnd(32, '0').slice(0, 32));
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const result = { ...payload };
  const encryptedSet = new Set(claimsToEncrypt);

  for (const claim of claimsToEncrypt) {
    if (claim in payload) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = utf8Encode(JSON.stringify(payload[claim]));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        key,
        plaintext as unknown as BufferSource
      );

      result[claim] = `enc_gcm.${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ciphertext))}`;
    }
  }

  result._enc = Array.from(encryptedSet);
  return result;
}

/**
 * Decrypt previously encrypted claims in a payload.
 */
export async function decryptClaims(
  payload: Record<string, any>,
  secret: string
): Promise<Record<string, any>> {
  if (!Array.isArray(payload._enc)) {
    return payload;
  }

  const crypto = globalThis.crypto;
  const rawKey = utf8Encode(secret.padEnd(32, '0').slice(0, 32));
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const result = { ...payload };

  for (const claim of payload._enc) {
    const val = result[claim];
    if (typeof val === 'string' && val.startsWith('enc_gcm.')) {
      const [, ivB64, cipherB64] = val.split('.');
      const iv = fromBase64Url(ivB64);
      const ciphertext = fromBase64Url(cipherB64);

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as BufferSource },
        key,
        ciphertext as unknown as BufferSource
      );

      result[claim] = JSON.parse(utf8Decode(new Uint8Array(decrypted)));
    }
  }

  delete result._enc;
  return result;
}
