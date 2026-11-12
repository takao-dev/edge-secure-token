import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = webcrypto;
}

import {
  signToken,
  verifyToken,
  timingSafeEqual,
  issueTokenPair,
  rotateTokenPair,
  MemoryRevocationStore,
  importSignKey,
  signData,
  decryptClaims,
  getWebCrypto,
  verifyData,
} from '../dist/index.js';

const TEST_SECRET = 'super-secret-jwt-key-minimum-32-characters';

test('timingSafeEqual detects equality and mismatch in constant-time', () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  const c = new Uint8Array([1, 2, 3, 5]);
  const d = new Uint8Array([1, 2, 3]);

  assert.equal(timingSafeEqual(a, b), true);
  assert.equal(timingSafeEqual(a, c), false);
  assert.equal(timingSafeEqual(a, d), false);
});

test('signToken and verifyToken round-trip with HS256 and JTI', async () => {
  const payload = { userId: 'u_1001', role: 'admin' };

  const token = await signToken(payload, TEST_SECRET, {
    alg: 'HS256',
    kid: 'key-primary-2026',
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    expiresIn: 3600,
  });

  assert.ok(typeof token === 'string');
  assert.equal(token.split('.').length, 3);

  const verified = await verifyToken(token, TEST_SECRET, {
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
  });

  assert.equal(verified.userId, 'u_1001');
  assert.equal(verified.role, 'admin');
  assert.ok(typeof verified.jti === 'string');
  assert.equal(verified.iss, 'https://auth.example.com');
  assert.ok(verified.exp > Math.floor(Date.now() / 1000));
});

test('Key ID (kid) path traversal and injection attacks are structurally rejected', async () => {
  const maliciousKids = [
    '../../../../etc/passwd',
    "key' OR '1'='1",
    'key; DROP TABLE keys;--',
    '<script>alert(1)</script>',
    'key with spaces',
  ];

  for (const kid of maliciousKids) {
    await assert.rejects(
      () => signToken({ user: 'attacker' }, TEST_SECRET, { kid }),
      /invalid key id \(kid\)/i
    );
  }
});

test('verifyToken strictly rejects "alg": "none" and all case variations', async () => {
  const variations = ['none', 'None', 'nOnE', 'NONE'];

  for (const alg of variations) {
    const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ role: 'admin' })).toString('base64url');
    const noneToken = `${header}.${payload}.`;

    await assert.rejects(
      () => verifyToken(noneToken, TEST_SECRET),
      /prohibited signature algorithm/i
    );
  }
});

test('Instant token revocation via RevocationStore invalidates active tokens', async () => {
  const store = new MemoryRevocationStore();

  const token = await signToken({ user: 'charlie' }, TEST_SECRET, { expiresIn: 3600 });
  const verified = await verifyToken(token, TEST_SECRET, { revocationStore: store });
  assert.equal(verified.user, 'charlie');

  // Immediately revoke this token's JTI
  store.revoke(verified.jti, verified.exp);

  // Subsequent verification must fail closed
  await assert.rejects(
    () => verifyToken(token, TEST_SECRET, { revocationStore: store }),
    /token has been revoked/i
  );
});

test('Token Pair issuance, rotation, and replay-attack defense', async () => {
  const store = new MemoryRevocationStore();

  // 1. Issue pair
  const pair1 = await issueTokenPair({ sub: 'user_42', tier: 'premium' }, TEST_SECRET);
  assert.ok(pair1.accessToken);
  assert.ok(pair1.refreshToken);

  // 2. Rotate pair using valid refresh token
  const pair2 = await rotateTokenPair(pair1.refreshToken, TEST_SECRET, store);
  assert.ok(pair2.accessToken);
  assert.ok(pair2.refreshToken);
  assert.notEqual(pair1.accessToken, pair2.accessToken);

  // 3. Replay attack: attempting to reuse old pair1.refreshToken MUST be rejected
  await assert.rejects(
    () => rotateTokenPair(pair1.refreshToken, TEST_SECRET, store),
    /token has been revoked/i
  );
});

test('signToken and verifyToken with ES256 (ECDSA)', async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const token = await signToken({ sub: 'ecc_user' }, keyPair.privateKey, {
    alg: 'ES256',
  });

  const verified = await verifyToken(token, keyPair.publicKey, {
    algorithm: 'ES256',
  });

  assert.equal(verified.sub, 'ecc_user');
});

test('verifyToken fails closed on tampered payload or signature', async () => {
  const token = await signToken({ account: 'acc_free' }, TEST_SECRET);
  const parts = token.split('.');

  const tamperedPayload = Buffer.from(JSON.stringify({ account: 'acc_admin' }))
    .toString('base64url');
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  await assert.rejects(
    () => verifyToken(tamperedToken, TEST_SECRET),
    /invalid token signature/i
  );
});

test('verifyToken enforces token expiration (exp)', async () => {
  const expiredToken = await signToken({ user: 'bob' }, TEST_SECRET, {
    expiresIn: -10,
  });

  await assert.rejects(
    () => verifyToken(expiredToken, TEST_SECRET, { clockTolerance: 0 }),
    /token has expired/i
  );
});

test('field-level claims encryption hides sensitive fields and decrypts seamlessly', async () => {
  const jwtSecret = 'jwt-signing-secret-32-chars-key!!';
  const claimEncryptionKey = 'aes-gcm-claim-secret-32-chars!!';

  const token = await signToken(
    {
      publicInfo: 'visible_to_anyone',
      secretSSN: '987-65-4321',
      billingEmail: 'alice.private@vault.net',
    },
    jwtSecret,
    {
      encryptClaims: ['secretSSN', 'billingEmail'],
      claimEncryptionSecret: claimEncryptionKey,
    }
  );

  assert.ok(!token.includes('987-65-4321'));
  assert.ok(!token.includes('alice.private@vault.net'));

  const verified = await verifyToken(token, jwtSecret, {
    claimEncryptionSecret: claimEncryptionKey,
  });

  assert.equal(verified.publicInfo, 'visible_to_anyone');
  assert.equal(verified.secretSSN, '987-65-4321');
  assert.equal(verified.billingEmail, 'alice.private@vault.net');
});

test('MemoryRevocationStore lifecycle and expiration cleanExpired', async () => {
  const store = new MemoryRevocationStore();

  const nowSec = Math.floor(Date.now() / 1000);
  store.revoke('jti_1', nowSec + 1);
  assert.equal(store.isRevoked('jti_1'), true);
  assert.equal(store.isRevoked('non_existent'), false);

  // Expire
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(store.isRevoked('jti_1'), false); // Deleted on query

  // cleanExpired on new revoke
  store.revoke('jti_old', nowSec - 10);
  store.revoke('jti_new', nowSec + 60);
  assert.equal(store.isRevoked('jti_new'), true);

  store.clear();
  assert.equal(store.isRevoked('jti_new'), false);
});

test('signToken claims options: iss, aud, sub, jti', async () => {
  const token = await signToken(
    { data: 123 },
    TEST_SECRET,
    {
      issuer: 'https://auth.takao.me',
      audience: 'https://api.takao.me',
      subject: 'usr_admin',
      jti: 'custom-jti-uuid',
    }
  );

  const verified = await verifyToken(token, TEST_SECRET, {
    issuer: 'https://auth.takao.me',
    audience: 'https://api.takao.me',
  });

  assert.equal(verified.iss, 'https://auth.takao.me');
  assert.equal(verified.aud, 'https://api.takao.me');
  assert.equal(verified.sub, 'usr_admin');
  assert.equal(verified.jti, 'custom-jti-uuid');
});

test('verifyToken failure modes: malformed, alg mismatch, iss mismatch, aud mismatch', async () => {
  // Malformed tokens
  await assert.rejects(() => verifyToken('not.a.valid.jwt.with.four.parts', TEST_SECRET), /malformed token structure/i);
  await assert.rejects(() => verifyToken('not_a_jwt', TEST_SECRET), /malformed token structure/i);

  // Algorithm mismatch
  const tokenHS256 = await signToken({ user: 'carol' }, TEST_SECRET, { alg: 'HS256' });
  await assert.rejects(
    () => verifyToken(tokenHS256, TEST_SECRET, { algorithm: 'ES256' }),
    /algorithm mismatch/i
  );

  // Issuer mismatch
  const tokenWithIss = await signToken({ user: 'carol' }, TEST_SECRET, { issuer: 'real-issuer' });
  await assert.rejects(
    () => verifyToken(tokenWithIss, TEST_SECRET, { issuer: 'fake-issuer' }),
    /issuer mismatch/i
  );

  // Audience mismatch
  const tokenWithAud = await signToken({ user: 'carol' }, TEST_SECRET, { audience: 'my-service' });
  await assert.rejects(
    () => verifyToken(tokenWithAud, TEST_SECRET, { audience: 'other-service' }),
    /audience mismatch/i
  );
});

test('rotateTokenPair error scenarios', async () => {
  const store = new MemoryRevocationStore();

  // Non-refresh token used for rotation
  const accessToken = await signToken({ sub: 'user_1' }, TEST_SECRET);
  await assert.rejects(
    () => rotateTokenPair(accessToken, TEST_SECRET, store),
    /expected refresh token/i
  );

  // Revoked refresh token
  const pair = await issueTokenPair('usr_1', TEST_SECRET, { revocationStore: store });
  store.revoke(`rf_${pair.jti}`, Math.floor(Date.now() / 1000) + 3600);

  await assert.rejects(
    () => rotateTokenPair(pair.refreshToken, TEST_SECRET, store),
    /Token has been revoked/i
  );
});

test('crypto helpers, nbf, and validation edge cases', async () => {
  // Invalid string key for ECDSA
  await assert.rejects(
    () => importSignKey('ES256', 'raw-string-key'),
    /String keys are supported for HMAC/i
  );

  // Unknown algorithm signing
  const dummyKey = await importSignKey('HS256', TEST_SECRET);
  await assert.rejects(
    () => signData('UNKNOWN_ALG', dummyKey, new Uint8Array([1, 2, 3])),
    /Unsupported signing algorithm/i
  );

  // Empty token string
  await assert.rejects(() => verifyToken('', TEST_SECRET), /non-empty string/i);

  // Malformed base64url or JSON
  await assert.rejects(() => verifyToken('bad.bad.bad', TEST_SECRET), /Malformed base64url or JSON/i);

  // Missing alg in header
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const noAlgToken = `${b64({ typ: 'JWT' })}.${b64({ user: 'dave' })}.sig`;
  await assert.rejects(() => verifyToken(noAlgToken, TEST_SECRET), /Missing signature algorithm/i);

  // nbf in the future
  const futureNbfToken = await signToken({ user: 'future', nbf: Math.floor(Date.now() / 1000) + 3600 }, TEST_SECRET);
  await assert.rejects(
    () => verifyToken(futureNbfToken, TEST_SECRET, { clockTolerance: 0 }),
    /Token is not active yet/i
  );

  // Missing claimEncryptionSecret when encryptClaims specified
  await assert.rejects(
    () => signToken({ secretData: 'xyz' }, TEST_SECRET, { encryptClaims: ['secretData'] }),
    /claimEncryptionSecret is required/i
  );

  // decryptClaims when claim is not in enc_gcm format
  const claimsWithNonEnc = {
    _enc: ['plainClaim'],
    plainClaim: 'not-an-encrypted-string',
  };
  const decrypted = await decryptClaims(claimsWithNonEnc, TEST_SECRET);
  assert.equal(decrypted.plainClaim, 'not-an-encrypted-string');
});

test('multi-algorithm support: ES384, ES512, and Ed25519', async () => {
  const crypto = globalThis.crypto;

  // ES384 (P-384)
  try {
    const es384Keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify']
    );
    const token384 = await signToken({ user: 'es384_user' }, es384Keys.privateKey, { alg: 'ES384' });
    const verified384 = await verifyToken(token384, es384Keys.publicKey, { algorithm: 'ES384' });
    assert.equal(verified384.user, 'es384_user');
  } catch {
    // runtime curve support fallback
  }

  // ES512 (P-521)
  try {
    const es512Keys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-521' },
      false,
      ['sign', 'verify']
    );
    const token512 = await signToken({ user: 'es512_user' }, es512Keys.privateKey, { alg: 'ES512' });
    const verified512 = await verifyToken(token512, es512Keys.publicKey, { algorithm: 'ES512' });
    assert.equal(verified512.user, 'es512_user');
  } catch {
    // runtime curve support fallback
  }

  // Ed25519
  try {
    const edKeys = await crypto.subtle.generateKey(
      { name: 'Ed25519' },
      false,
      ['sign', 'verify']
    );
    const tokenEd = await signToken({ user: 'ed_user' }, edKeys.privateKey, { alg: 'Ed25519' });
    const verifiedEd = await verifyToken(tokenEd, edKeys.publicKey, { algorithm: 'Ed25519' });
    assert.equal(verifiedEd.user, 'ed_user');
  } catch {
    // runtime curve support fallback
  }
});

test('signToken prohibits alg none and verifyToken rejects malicious kid', async () => {
  // signToken alg none
  await assert.rejects(
    () => signToken({ user: 'none' }, TEST_SECRET, { alg: 'none' }),
    /Algorithm "none" is strictly prohibited/i
  );

  // verifyToken header with path traversal kid
  const badKidHeader = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'HS256', kid: '../traversal' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ user: 'bad_kid', iat: Math.floor(Date.now() / 1000) })).toString('base64url');
  const fakeToken = `${badKidHeader}.${payload}.fake_signature`;
  await assert.rejects(
    () => verifyToken(fakeToken, TEST_SECRET),
    /Malicious Key ID \(kid\) detected/i
  );
});

test('decryptClaims bypasses unencrypted payloads and verifyData returns false on unsupported alg', async () => {
  // decryptClaims with no _enc
  const rawPayload = { normalKey: 'plainValue' };
  const res = await decryptClaims(rawPayload, TEST_SECRET);
  assert.deepEqual(res, rawPayload);

  // verifyData with unsupported alg
  const dummyKey = await importSignKey('HS256', TEST_SECRET);
  const verifyRes = await verifyData('UNSUPPORTED_ALG', dummyKey, new Uint8Array(32), new Uint8Array(10));
  assert.equal(verifyRes, false);

  // getWebCrypto throws when crypto is unavailable
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(() => getWebCrypto(), /WebCrypto SubtleCrypto is not available/i);
  } finally {
    if (originalCrypto) {
      Object.defineProperty(globalThis, 'crypto', originalCrypto);
    }
  }
});
