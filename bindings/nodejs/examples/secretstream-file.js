'use strict';

// crypto_secretstream: encrypt/decrypt a file incrementally, chunk by chunk, via the
// stream.Transform SecretStreamEncryptor/SecretStreamDecryptor pair (docs/DECISIONS.md D-118).
// The wire format matches `uacrypt encrypt`/`decrypt` exactly - a file this writes is decryptable
// by the `uacrypt` CLI and vice versa.
//
// Run: node examples/secretstream-file.js

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { finished } = require('node:stream/promises');
const dstu = require('../js/index.js');

async function encryptToFile(key, plaintext, outPath) {
  const enc = new dstu.SecretStreamEncryptor(key);
  enc.pipe(fs.createWriteStream(outPath));
  enc.end(plaintext);
  await finished(enc);
}

async function decryptFileToBuffer(key, inPath) {
  const dec = new dstu.SecretStreamDecryptor(key);
  const chunks = [];
  dec.on('data', (chunk) => chunks.push(chunk));
  fs.createReadStream(inPath).pipe(dec);
  await finished(dec);
  return Buffer.concat(chunks);
}

async function main() {
  const key = dstu.secretstreamKeygen();
  const plaintext = Buffer.from('a message spread across more than one 8 KiB chunk\n'.repeat(1000));

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstu-node-example-'));
  try {
    const encryptedPath = path.join(tmpDir, 'message.enc');
    const decryptedPath = path.join(tmpDir, 'message.dec');

    await encryptToFile(key, plaintext, encryptedPath);
    const recovered = await decryptFileToBuffer(key, encryptedPath);

    assert.deepStrictEqual(recovered, plaintext);
    const encryptedSize = fs.statSync(encryptedPath).size;
    console.log(`${plaintext.length} bytes -> ${encryptedSize} bytes on disk, round-tripped OK`);
    fs.writeFileSync(decryptedPath, recovered);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
