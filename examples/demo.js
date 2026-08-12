const {
  encrypt,
  decryptToString,
  deriveKey,
  generateSalt,
  hmacSign,
  hmacVerify,
  generateKeyPair,
  rsaEncrypt,
  rsaDecrypt,
} = require("../dist/index.js");

async function main() {
  // AES-256-GCM with a scrypt-derived key
  const salt = generateSalt();
  const key = await deriveKey("correct horse battery staple", { salt });
  const payload = encrypt("the treasure is buried at midnight", key);
  console.log(`AES-GCM payload (base64, len ${payload.length}): ${payload.slice(0, 40)}...`);
  const recovered = decryptToString(payload, key);
  console.log(`Decrypted: "${recovered}"`);

  try {
    // tamper with the payload to prove auth-tag verification works
    const tampered = payload.slice(0, -4) + "AAAA";
    decryptToString(tampered, key);
    console.log("ERROR: tampered payload should have thrown");
  } catch {
    console.log("Tampered payload correctly rejected (auth tag mismatch)");
  }

  // HMAC-SHA256
  const hmacKey = Buffer.from("shared-secret");
  const sig = hmacSign("order:42:amount:100", hmacKey);
  console.log(`\nHMAC signature: ${sig}`);
  console.log(`Verify (correct):   ${hmacVerify("order:42:amount:100", sig, hmacKey)}`);
  console.log(`Verify (tampered):  ${hmacVerify("order:42:amount:999", sig, hmacKey)}`);

  // RSA-OAEP
  console.log("\nGenerating RSA-2048 key pair...");
  const { publicKey, privateKey } = await generateKeyPair(2048);
  const rsaPayload = rsaEncrypt("small secret for RSA", publicKey);
  const rsaRecovered = rsaDecrypt(rsaPayload, privateKey).toString("utf8");
  console.log(`RSA-OAEP round trip: "${rsaRecovered}"`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
