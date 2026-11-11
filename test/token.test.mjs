import test from 'node:test';
import assert from 'node:assert/strict';
import {
  signToken,
  verifyToken,
  timingSafeEqual,
} from '../dist/index.js';

test('timingSafeEqual detects equality and mismatch in constant-time', () => {
  const a = new Uint8Array([1, 2, 3, 4]);
  const b = new Uint8Array([1, 2, 3, 4]);
  const c = new Uint8Array([1, 2, 3, 5]);
  const d = new Uint8Array([1, 2, 3]);

  assert.equal(timingSafeEqual(a, b), true);
  assert.equal(timingSafeEqual(a, c), false);
  assert.equal(timingSafeEqual(a, d), false);
});

test('signToken and verifyToken round-trip with HS256', async () => {
  const secret = 'super-secret-jwt-key-minimum-32-characters';
  const payload = { userId: 'u_1001', role: 'admin' };

  const token = await signToken(payload, secret, {
    alg: 'HS256',
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
    expiresIn: 3600,
  });

  assert.ok(typeof token === 'string');
  assert.equal(token.split('.').length, 3);

  const verified = await verifyToken(token, secret, {
    issuer: 'https://auth.example.com',
    audience: 'https://api.example.com',
  });

  assert.equal(verified.userId, 'u_1001');
  assert.equal(verified.role, 'admin');
  assert.equal(verified.iss, 'https://auth.example.com');
  assert.ok(verified.exp > Math.floor(Date.now() / 1000));
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
  const secret = 'super-secret-jwt-key-minimum-32-characters';
  const token = await signToken({ account: 'acc_free' }, secret);

  const parts = token.split('.');
  // Tamper with payload to escalate privileges
  const tamperedPayload = Buffer.from(JSON.stringify({ account: 'acc_admin' }))
    .toString('base64url');
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  await assert.rejects(
    () => verifyToken(tamperedToken, secret),
    /invalid token signature/i
  );
});

test('verifyToken strictly rejects "alg": "none" attacks', async () => {
  const header = Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'none' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ role: 'admin' })).toString('base64url');
  const noneToken = `${header}.${payload}.`;

  await assert.rejects(
    () => verifyToken(noneToken, 'any-key'),
    /missing or prohibited signature algorithm/i
  );
});

test('verifyToken enforces token expiration (exp)', async () => {
  const secret = 'super-secret-jwt-key-minimum-32-characters';
  const expiredToken = await signToken({ user: 'bob' }, secret, {
    expiresIn: -10, // already expired 10 seconds ago
  });

  await assert.rejects(
    () => verifyToken(expiredToken, secret, { clockTolerance: 0 }),
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

  // Raw token must NOT contain the sensitive values
  assert.ok(!token.includes('987-65-4321'));
  assert.ok(!token.includes('alice.private@vault.net'));

  // Verifying with claimEncryptionSecret decrypts them transparently
  const verified = await verifyToken(token, jwtSecret, {
    claimEncryptionSecret: claimEncryptionKey,
  });

  assert.equal(verified.publicInfo, 'visible_to_anyone');
  assert.equal(verified.secretSSN, '987-65-4321');
  assert.equal(verified.billingEmail, 'alice.private@vault.net');
});
