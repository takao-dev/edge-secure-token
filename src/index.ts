/**
 * edge-secure-token: Zero-dependency, WebCrypto-native, timing-safe JWT and token suite.
 * Built for Cloudflare Workers, Edge, and Node.js with field-level claims encryption and revocation.
 */

export * from './base64url.js';
export * from './crypto.js';
export * from './revocation.js';

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
import { RevocationStore, MemoryRevocationStore } from './revocation.js';

export interface TokenSignOptions {
  /** Signature algorithm. Defaults to 'HS256'. */
  alg?: SupportedAlgorithm;
  /** Key ID (kid) header parameter. Must be alphanumeric (plus hyphen/underscore). */
  kid?: string;
  /** Token lifetime in seconds (sets exp claim). */
  expiresIn?: number;
  /** Issuer claim (iss). */
  issuer?: string;
  /** Audience claim (aud). */
  audience?: string | string[];
  /** Subject claim (sub). */
  subject?: string;
  /** JWT ID (jti) claim. Defaults to cryptographically generated UUID/random ID. */
  jti?: string;
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
  /** Optional revocation store to check for blacklisted jti tokens. */
  revocationStore?: RevocationStore;
  /** Secret used to decrypt field-level encrypted claims. */
  claimEncryptionSecret?: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  jti: string;
  expiresIn: number;
}

const KID_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

function generateSecureId(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
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
  const normalizedAlg = String(alg).trim().toLowerCase();
  if (normalizedAlg === 'none') {
    throw new Error('Algorithm "none" is strictly prohibited');
  }

  if (options.kid) {
    if (!KID_REGEX.test(options.kid)) {
      throw new Error('Invalid Key ID (kid): must be 1-64 alphanumeric, hyphen, or underscore characters');
    }
  }

  const header: Record<string, any> = {
    typ: 'JWT',
    alg,
  };
  if (options.kid) {
    header.kid = options.kid;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const jti = options.jti ?? generateSecureId();

  let finalPayload: Record<string, any> = {
    iat: nowSec,
    jti,
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
 * Verify and decode a token, verifying signature, expiration, issuer, audience, and revocation.
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
  let header: { typ?: string; alg?: string; kid?: string };
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
  if (!alg) {
    throw new Error('Missing signature algorithm in token header');
  }

  const normalizedAlg = String(alg).trim().toLowerCase();
  if (normalizedAlg === 'none') {
    throw new Error('Prohibited signature algorithm: "none"');
  }

  if (header.kid && !KID_REGEX.test(header.kid)) {
    throw new Error('Malicious Key ID (kid) detected');
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

  // Check revocation store
  if (options.revocationStore && payload.jti) {
    const isRevoked = await options.revocationStore.isRevoked(payload.jti);
    if (isRevoked) {
      throw new Error('Token has been revoked');
    }
  }

  // Decrypt field-level encrypted claims if present
  if (options.claimEncryptionSecret && Array.isArray(payload._enc)) {
    payload = await decryptClaims(payload, options.claimEncryptionSecret);
  }

  return payload as T;
}

/**
 * Issue a dual Access Token (short-lived) + Refresh Token (long-lived, one-time) pair.
 */
export async function issueTokenPair(
  payload: Record<string, any>,
  key: string | CryptoKey,
  options: {
    accessTtl?: number;
    refreshTtl?: number;
    issuer?: string;
    audience?: string;
  } = {}
): Promise<TokenPair> {
  const accessTtl = options.accessTtl ?? 900; // 15 mins
  const refreshTtl = options.refreshTtl ?? 604800; // 7 days

  const jti = generateSecureId();

  const accessToken = await signToken(
    { ...payload, token_type: 'access' },
    key,
    {
      expiresIn: accessTtl,
      issuer: options.issuer,
      audience: options.audience,
      jti,
    }
  );

  const refreshToken = await signToken(
    { ...payload, token_type: 'refresh' },
    key,
    {
      expiresIn: refreshTtl,
      issuer: options.issuer,
      audience: options.audience,
      jti: `rf_${jti}`,
    }
  );

  return {
    accessToken,
    refreshToken,
    jti,
    expiresIn: accessTtl,
  };
}

/**
 * Rotate an existing token pair using a valid refresh token.
 * Prevents replay attacks by immediately revoking the used refresh token JTI.
 */
export async function rotateTokenPair(
  oldRefreshToken: string,
  key: string | CryptoKey,
  revocationStore: RevocationStore,
  options: {
    accessTtl?: number;
    refreshTtl?: number;
    issuer?: string;
    audience?: string;
  } = {}
): Promise<TokenPair> {
  const verified = await verifyToken<{ jti: string; token_type: string; exp: number }>(
    oldRefreshToken,
    key,
    {
      issuer: options.issuer,
      audience: options.audience,
      revocationStore,
    }
  );

  if (verified.token_type !== 'refresh') {
    throw new Error('Invalid token type; expected refresh token');
  }

  // Revoke the old refresh token JTI immediately to prevent replay attacks
  await revocationStore.revoke(verified.jti, verified.exp);

  // Issue new pair
  const { jti, token_type, exp, iat, ...userClaims } = verified as any;
  return issueTokenPair(userClaims, key, options);
}
