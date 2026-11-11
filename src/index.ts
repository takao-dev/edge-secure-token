/**
 * edge-secure-token: Zero-dependency, WebCrypto-native, timing-safe JWT and token suite.
 * Built for Cloudflare Workers, Edge, and Node.js with field-level claims encryption.
 */

export * from './base64url.js';
export * from './crypto.js';

import {
  toBase64Url,
  fromBase64Url,
  utf8Encode,
  utf8Decode,
} from './base64url.js';
import {
  SupportedAlgorithm,
  importSignKey,
  signData,
  verifyData,
  encryptClaims,
  decryptClaims,
} from './crypto.js';

export interface TokenSignOptions {
  /** Signature algorithm. Defaults to 'HS256'. */
  alg?: SupportedAlgorithm;
  /** Token lifetime in seconds (sets exp claim). */
  expiresIn?: number;
  /** Issuer claim (iss). */
  issuer?: string;
  /** Audience claim (aud). */
  audience?: string | string[];
  /** Subject claim (sub). */
  subject?: string;
  /** Specific claims to encrypt with AES-GCM for field-level privacy. */
  encryptClaims?: string[];
  /** Secret used to encrypt specific claims. */
  claimEncryptionSecret?: string;
}

export interface TokenVerifyOptions {
  /** Expected algorithm. If specified, rejects tokens signed with another algorithm. */
  algorithm?: SupportedAlgorithm;
  /** Expected issuer (iss). */
  issuer?: string;
  /** Expected audience (aud). */
  audience?: string;
  /** Allowed clock drift in seconds. Defaults to 60s. */
  clockTolerance?: number;
  /** Secret used to decrypt field-level encrypted claims. */
  claimEncryptionSecret?: string;
}

/**
 * Sign an arbitrary payload into a secure compact token (header.payload.signature).
 */
export async function signToken(
  payload: Record<string, any>,
  key: string | CryptoKey,
  options: TokenSignOptions = {}
): Promise<string> {
  const alg = options.alg ?? 'HS256';
  if (alg === ('none' as any)) {
    throw new Error('Algorithm "none" is strictly prohibited');
  }

  const header = {
    typ: 'JWT',
    alg,
  };

  const nowSec = Math.floor(Date.now() / 1000);
  let finalPayload: Record<string, any> = {
    iat: nowSec,
    ...payload,
  };

  if (typeof options.expiresIn === 'number') {
    finalPayload.exp = nowSec + options.expiresIn;
  }
  if (options.issuer) {
    finalPayload.iss = options.issuer;
  }
  if (options.audience) {
    finalPayload.aud = options.audience;
  }
  if (options.subject) {
    finalPayload.sub = options.subject;
  }

  // Field-level claims encryption
  if (options.encryptClaims && options.encryptClaims.length > 0) {
    if (!options.claimEncryptionSecret) {
      throw new Error('claimEncryptionSecret is required when encryptClaims is specified');
    }
    finalPayload = await encryptClaims(finalPayload, options.encryptClaims, options.claimEncryptionSecret);
  }

  const encodedHeader = toBase64Url(utf8Encode(JSON.stringify(header)));
  const encodedPayload = toBase64Url(utf8Encode(JSON.stringify(finalPayload)));
  const signingInput = utf8Encode(`${encodedHeader}.${encodedPayload}`);

  const cryptoKey = await importSignKey(alg, key);
  const signatureBytes = await signData(alg, cryptoKey, signingInput);
  const encodedSignature = toBase64Url(signatureBytes);

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verify and decode a token, verifying signature, expiration, issuer, and audience.
 */
export async function verifyToken<T = Record<string, any>>(
  token: string,
  key: string | CryptoKey,
  options: TokenVerifyOptions = {}
): Promise<T> {
  if (typeof token !== 'string' || !token) {
    throw new Error('Token must be a non-empty string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed token structure; expected header.payload.signature');
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  let header: { typ?: string; alg?: string };
  let payload: Record<string, any>;
  let signature: Uint8Array;

  try {
    header = JSON.parse(utf8Decode(fromBase64Url(headerB64)));
    payload = JSON.parse(utf8Decode(fromBase64Url(payloadB64)));
    signature = fromBase64Url(signatureB64);
  } catch {
    throw new Error('Malformed base64url or JSON in token');
  }

  const alg = header.alg as SupportedAlgorithm;
  if (!alg || (alg as string) === 'none') {
    throw new Error('Missing or prohibited signature algorithm');
  }
  if (options.algorithm && options.algorithm !== alg) {
    throw new Error(`Algorithm mismatch: expected ${options.algorithm}, got ${alg}`);
  }

  const signingInput = utf8Encode(`${headerB64}.${payloadB64}`);
  const cryptoKey = await importSignKey(alg, key);
  const isValid = await verifyData(alg, cryptoKey, signature, signingInput);

  if (!isValid) {
    throw new Error('Invalid token signature');
  }

  // Validate time claims
  const nowSec = Math.floor(Date.now() / 1000);
  const tolerance = options.clockTolerance ?? 60;

  if (typeof payload.exp === 'number' && nowSec - tolerance >= payload.exp) {
    throw new Error('Token has expired');
  }
  if (typeof payload.nbf === 'number' && nowSec + tolerance < payload.nbf) {
    throw new Error('Token is not active yet (nbf)');
  }

  // Validate issuer & audience
  if (options.issuer && payload.iss !== options.issuer) {
    throw new Error(`Issuer mismatch: expected ${options.issuer}, got ${payload.iss}`);
  }
  if (options.audience) {
    const aud = payload.aud;
    const audMatches = Array.isArray(aud) ? aud.includes(options.audience) : aud === options.audience;
    if (!audMatches) {
      throw new Error(`Audience mismatch: expected ${options.audience}`);
    }
  }

  // Decrypt field-level encrypted claims if present
  if (options.claimEncryptionSecret && Array.isArray(payload._enc)) {
    payload = await decryptClaims(payload, options.claimEncryptionSecret);
  }

  return payload as T;
}
