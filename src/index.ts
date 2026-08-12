import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  generateKeyPair as nodeGenerateKeyPair,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  constants as cryptoConstants,
} from "node:crypto";

function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number }
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

const AES_ALGORITHM = "aes-256-gcm";
const AES_IV_LENGTH = 12; // 96-bit IV, the GCM-recommended size
const AES_KEY_LENGTH = 32; // 256 bits
const AES_AUTH_TAG_LENGTH = 16;

/**
 * Encrypt `plaintext` with AES-256-GCM under `key` (exactly 32 bytes).
 *
 * Output is a single portable string: base64(iv || ciphertext || authTag),
 * so callers only have to store/transmit one value.
 */
export function encrypt(plaintext: string | Buffer, key: Buffer): string {
  if (key.length !== AES_KEY_LENGTH) {
    throw new Error(`encrypt: key must be ${AES_KEY_LENGTH} bytes (got ${key.length})`);
  }
  const iv = randomBytes(AES_IV_LENGTH);
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);
  const input = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, authTag]).toString("base64");
}

/**
 * Decrypt a payload produced by `encrypt`. Throws if the auth tag doesn't
 * verify (tampered ciphertext / wrong key).
 */
export function decrypt(payload: string, key: Buffer): Buffer {
  if (key.length !== AES_KEY_LENGTH) {
    throw new Error(`decrypt: key must be ${AES_KEY_LENGTH} bytes (got ${key.length})`);
  }
  const raw = Buffer.from(payload, "base64");
  if (raw.length < AES_IV_LENGTH + AES_AUTH_TAG_LENGTH) {
    throw new Error("decrypt: payload too short to be valid");
  }
  const iv = raw.subarray(0, AES_IV_LENGTH);
  const authTag = raw.subarray(raw.length - AES_AUTH_TAG_LENGTH);
  const ciphertext = raw.subarray(AES_IV_LENGTH, raw.length - AES_AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(AES_ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Convenience wrapper: decrypt and return a utf8 string. */
export function decryptToString(payload: string, key: Buffer): string {
  return decrypt(payload, key).toString("utf8");
}

// ---------------------------------------------------------------------------
// Key derivation (scrypt)
// ---------------------------------------------------------------------------

export interface DeriveKeyOptions {
  /** Salt bytes. Generate with `randomBytes(16)` and store it alongside the ciphertext. */
  salt: Buffer;
  /** Output key length in bytes. Default 32 (AES-256). */
  keyLength?: number;
  /** scrypt cost parameter. Default 16384 (2^14). */
  N?: number;
  /** scrypt block size parameter. Default 8. */
  r?: number;
  /** scrypt parallelization parameter. Default 1. */
  p?: number;
}

/** Derive a symmetric key from a human passphrase using scrypt. */
export async function deriveKey(passphrase: string, options: DeriveKeyOptions): Promise<Buffer> {
  const keyLength = options.keyLength ?? AES_KEY_LENGTH;
  const N = options.N ?? 16384;
  const r = options.r ?? 8;
  const p = options.p ?? 1;
  // scrypt's memory cost is roughly 128 * N * r bytes; Node enforces a default
  // 32MB ceiling, so we raise maxmem proportionally for larger N/r choices.
  const maxmem = Math.max(32 * 1024 * 1024, 128 * N * r * 2);
  const derived = await scrypt(passphrase, options.salt, keyLength, { N, r, p, maxmem });
  return derived;
}

/** Generate a fresh random salt for `deriveKey`. Default 16 bytes. */
export function generateSalt(length = 16): Buffer {
  return randomBytes(length);
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

/** Sign `data` with HMAC-SHA256 under `key`. Returns a hex digest. */
export function hmacSign(data: string | Buffer, key: Buffer | string): string {
  return createHmac("sha256", key).update(data).digest("hex");
}

/**
 * Verify an HMAC-SHA256 signature using a timing-safe comparison.
 * Returns false (never throws) for malformed signatures.
 */
export function hmacVerify(data: string | Buffer, signature: string, key: Buffer | string): boolean {
  const expected = createHmac("sha256", key).update(data).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

// ---------------------------------------------------------------------------
// RSA-OAEP
// ---------------------------------------------------------------------------

export interface RsaKeyPair {
  publicKey: string; // PEM, SPKI
  privateKey: string; // PEM, PKCS8
}

/** Generate an RSA key pair suitable for `rsaEncrypt`/`rsaDecrypt`. Default 2048-bit modulus. */
export async function generateKeyPair(modulusLength = 2048): Promise<RsaKeyPair> {
  return new Promise((resolve, reject) => {
    nodeGenerateKeyPair(
      "rsa",
      {
        modulusLength,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      },
      (err, publicKey, privateKey) => {
        if (err) reject(err);
        else resolve({ publicKey, privateKey });
      }
    );
  });
}

/** Encrypt with RSA-OAEP (SHA-256) under a PEM public key. Returns base64. */
export function rsaEncrypt(plaintext: string | Buffer, publicKeyPem: string): string {
  const input = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const encrypted = publicEncrypt(
    { key: publicKeyPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    input
  );
  return encrypted.toString("base64");
}

/** Decrypt an RSA-OAEP (SHA-256) payload under a PEM private key. */
export function rsaDecrypt(payload: string, privateKeyPem: string): Buffer {
  const encrypted = Buffer.from(payload, "base64");
  return privateDecrypt(
    { key: privateKeyPem, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    encrypted
  );
}
