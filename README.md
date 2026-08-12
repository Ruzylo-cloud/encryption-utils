# encryption-utils
![CI](https://github.com/FerrowAI/encryption-utils/actions/workflows/ci.yml/badge.svg)

Small, real implementations of the crypto primitives you actually reach
for, built directly on Node's `crypto` module. No third-party dependency,
no home-grown cipher — just a sane API around what Node already ships.

**Not audited.** This is for general-purpose application use (encrypting
config, signing tokens, protecting stored secrets), not for life-safety
or regulatory-compliance systems. Get a real audit before using this for
anything with legal or safety consequences.

## Install

```bash
npm install encryption-utils
```

## Quickstart

```ts
import { encrypt, decryptToString, deriveKey, generateSalt } from "encryption-utils";

const salt = generateSalt();
const key = await deriveKey("a user passphrase", { salt }); // 32-byte AES-256 key

const payload = encrypt("secret message", key);
// store `payload` and `salt` (salt is not secret, but is required to re-derive the key)

const plaintext = decryptToString(payload, key);
```

## API

### AES-256-GCM

- `encrypt(plaintext: string | Buffer, key: Buffer): string`
  Encrypts with a random 96-bit IV. Returns a single base64 string:
  `base64(iv[12] || ciphertext || authTag[16])` — one value to store or
  transmit, no separate IV/tag bookkeeping.
- `decrypt(payload: string, key: Buffer): Buffer`
  Throws if the auth tag doesn't verify (wrong key or tampered ciphertext).
- `decryptToString(payload: string, key: Buffer): string`
  Convenience wrapper returning utf8.

`key` must be exactly 32 bytes (AES-256). Use `deriveKey` to get one from
a passphrase, or `randomBytes(32)` for a machine-generated key.

### Key derivation (scrypt)

- `deriveKey(passphrase: string, options: DeriveKeyOptions): Promise<Buffer>`
  `DeriveKeyOptions`: `{ salt: Buffer, keyLength?: 32, N?: 16384, r?: 8, p?: 1 }`.
  `maxmem` is computed internally and raised automatically for larger
  `N`/`r` so Node's default 32MB scrypt ceiling doesn't surprise you.
- `generateSalt(length = 16): Buffer`

### HMAC-SHA256

- `hmacSign(data: string | Buffer, key: Buffer | string): string` — hex digest.
- `hmacVerify(data, signature: string, key): boolean` — timing-safe
  comparison via `crypto.timingSafeEqual`; returns `false` (never throws)
  for malformed input.

### RSA-OAEP

- `generateKeyPair(modulusLength = 2048): Promise<{ publicKey, privateKey }>`
  PEM-encoded, SPKI/PKCS8.
- `rsaEncrypt(plaintext: string | Buffer, publicKeyPem: string): string` — base64.
- `rsaDecrypt(payload: string, privateKeyPem: string): Buffer`

Both use OAEP padding with SHA-256, matching modern defaults (`RSA_PKCS1_OAEP_PADDING`,
`oaepHash: "sha256"`). RSA-OAEP payload size is bounded by the key size
(~190 bytes of plaintext for a 2048-bit key) — for larger payloads,
encrypt the data with AES-256-GCM and use RSA only to wrap the AES key.

## Design notes

Every function here is a thin, explicit wrapper over Node's built-in
`crypto` — no bundled cipher implementation, no dependency to audit
beyond Node itself. The AES payload format packs IV + ciphertext + auth
tag into one base64 string specifically so callers can't forget to store
the IV or tag separately (a common source of "it encrypted fine but I
can't decrypt it" bugs). `hmacVerify` uses `timingSafeEqual` rather than
`===` because a naive string comparison leaks timing information an
attacker can use to forge signatures byte-by-byte.

---

Sponsored by [Ferrow](https://ferrow.ai)

---
Part of the [ferrow-toolkit](https://github.com/FerrowAI/ferrow-toolkit) collection · Sponsored by [Ferrow](https://ferrow.ai)
