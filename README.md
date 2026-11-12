# edge-secure-token

Zero-dependency, timing-safe WebCrypto JWT suite for Cloudflare Workers, Edge, and Node.js with native field-level claims encryption.

[![npm version](https://img.shields.io/npm/v/edge-secure-token.svg)](https://www.npmjs.com/package/edge-secure-token)
[![CI](https://github.com/takao-dev/edge-secure-token/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/edge-secure-token/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/edge-secure-token/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/edge-secure-token)
[![CodeQL](https://github.com/takao-dev/edge-secure-token/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/edge-secure-token/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **Zero Runtime Dependencies**: Built directly on native WebCrypto `SubtleCrypto`.
- **Timing-Attack Immunity**: Uses constant-time signature comparisons to prevent side-channel leaks.
- **Strict "alg: none" Defense**: Structurally prohibits unsigned tokens and algorithm confusion.
- **Field-Level Claims Encryption**: Encrypt specific sensitive claims with AES-256-GCM while keeping the rest of the payload readable.
- **Universal Multi-Runtime Compatibility**: Runs seamlessly on Cloudflare Workers, Node.js 18+, Deno, Bun, and browser runtimes.

---

## Usage

### 1. Basic Token Signing and Verification

```typescript
import { signToken, verifyToken } from 'edge-secure-token';

const secret = 'super-secret-key-32-characters-minimum';

// Sign token
const token = await signToken({ userId: 'u_123', role: 'admin' }, secret, {
  expiresIn: 3600, // 1 hour
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});

// Verify token
const payload = await verifyToken(token, secret, {
  issuer: 'https://auth.example.com',
  audience: 'https://api.example.com',
});
console.log(payload.userId); // 'u_123'
```

### 2. Field-Level Claims Encryption

```typescript
const token = await signToken(
  {
    publicName: 'Alice',
    privateEmail: 'alice@internal.corp',
  },
  jwtSecret,
  {
    encryptClaims: ['privateEmail'],
    claimEncryptionSecret: aesSecret,
  }
);

// Decrypting transparently during verification
const verified = await verifyToken(token, jwtSecret, {
  claimEncryptionSecret: aesSecret,
});
console.log(verified.privateEmail); // 'alice@internal.corp'
```

---

## License

SPDX-License-Identifier: MIT
Copyright (c) 2026 takao-dev
