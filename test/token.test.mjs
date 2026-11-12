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
