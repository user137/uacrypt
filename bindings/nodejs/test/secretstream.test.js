'use strict';

/**
 * `crypto_secretstream` - both the low-level `SecretStreamPushState`/`PullState` (step 2) and the
 * `stream.Transform` pair `SecretStreamEncryptor`/`SecretStreamDecryptor` (step 3, D-118). Three
 * categories per D-64/D-65: correctness (round trip across chunk-boundary sizes, plus real
 * byte-for-byte interop with `uacrypt encrypt`/`decrypt`'s own wire format), rejection (tamper,
 * oversized chunk, trailing data), misuse (wrong-length key, write-after-end). Mirrors
 * bindings/python/tests/test_secretstream.py, including both D-118 pitfalls re-checked in D-127.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const dstu = require('../js/index.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const UACRYPT_CANDIDATES = [
  path.join(REPO_ROOT, 'target', 'debug', 'uacrypt.exe'),
  path.join(REPO_ROOT, 'target', 'release', 'uacrypt.exe'),
  path.join(REPO_ROOT, 'target', 'debug', 'uacrypt'),
  path.join(REPO_ROOT, 'target', 'release', 'uacrypt'),
];

function findUacrypt() {
  return UACRYPT_CANDIDATES.find((p) => fs.existsSync(p)) ?? null;
}

/**
 * Writes `input` into `transform` and reads its output back via a single async-iteration
 * consumer - deliberately not `stream.promises.pipeline()` plus a separate reader in parallel,
 * which double-consumes the same duplex stream and races two independent error paths (a real bug
 * found writing this test suite: it produced spurious "asynchronous activity after the test
 * ended" / unhandledRejection warnings under node:test's stricter runner, even though the
 * underlying wrapper code was correct - the bug was in this test helper, not in
 * SecretStreamEncryptor/Decryptor).
 */
async function runThrough(transform, input) {
  const chunks = [];
  const reading = (async () => {
    for await (const c of transform) chunks.push(c);
  })();
  for (const piece of input) {
    if (!transform.write(piece)) {
      await new Promise((resolve) => transform.once('drain', resolve));
    }
  }
  transform.end();
  await reading;
  return Buffer.concat(chunks);
}

function encryptAll(key, plaintext) {
  return runThrough(new dstu.SecretStreamEncryptor(key), [plaintext]);
}

function decryptAll(key, ciphertext) {
  return runThrough(new dstu.SecretStreamDecryptor(key), [ciphertext]);
}

test('round trip across chunk boundary sizes', async () => {
  const key = dstu.secretstreamKeygen();
  for (const size of [0, 1, 100, 8 * 1024, 8 * 1024 + 1, 8 * 1024 * 3, 8 * 1024 * 3 + 777]) {
    const plaintext = require('node:crypto').randomBytes(size);
    const ciphertext = await encryptAll(key, plaintext);
    const decrypted = await decryptAll(key, ciphertext);
    assert.deepStrictEqual(decrypted, plaintext, `size ${size}`);
  }
});

test('interop with the uacrypt CLI', { skip: findUacrypt() === null ? 'uacrypt binary not built (cargo build -p uacrypt)' : false }, async () => {
  const uacrypt = findUacrypt();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dstu-node-test-'));
  try {
    const key = dstu.secretstreamKeygen();
    const keyPath = path.join(tmpDir, 'key.bin');
    fs.writeFileSync(keyPath, key);
    const plaintext = require('node:crypto').randomBytes(8 * 1024 * 2 + 555);
    const plainPath = path.join(tmpDir, 'plain.bin');
    fs.writeFileSync(plainPath, plaintext);

    const nodeEncryptedPath = path.join(tmpDir, 'node_encrypted.bin');
    fs.writeFileSync(nodeEncryptedPath, await encryptAll(key, plaintext));

    const uacryptDecryptedPath = path.join(tmpDir, 'uacrypt_decrypted.bin');
    execFileSync(uacrypt, ['decrypt', '--key', keyPath, '--in', nodeEncryptedPath, '--out', uacryptDecryptedPath]);
    assert.deepStrictEqual(fs.readFileSync(uacryptDecryptedPath), plaintext);

    const uacryptEncryptedPath = path.join(tmpDir, 'uacrypt_encrypted.bin');
    execFileSync(uacrypt, ['encrypt', '--key', keyPath, '--in', plainPath, '--out', uacryptEncryptedPath]);
    const decrypted = await decryptAll(key, fs.readFileSync(uacryptEncryptedPath));
    assert.deepStrictEqual(decrypted, plaintext);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('tampered chunk is rejected', async () => {
  const key = dstu.secretstreamKeygen();
  const ciphertext = Buffer.from(await encryptAll(key, Buffer.from('secret message')));
  ciphertext[ciphertext.length - 1] ^= 1; // last byte of the Final chunk's auth tag
  await assert.rejects(() => decryptAll(key, ciphertext));
});

test('truncated stream is rejected', async () => {
  const key = dstu.secretstreamKeygen();
  const ciphertext = await encryptAll(key, Buffer.from('x'.repeat(20000)));
  const truncated = ciphertext.subarray(0, 100);
  await assert.rejects(() => decryptAll(key, truncated));
});

test('oversized declared chunk length is rejected', async () => {
  const key = dstu.secretstreamKeygen();
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(0xffffffff, 0);
  const malicious = Buffer.concat([Buffer.alloc(32), Buffer.from([0x00]), lenBuf]);
  await assert.rejects(() => decryptAll(key, malicious), /too large/);
});

test('trailing data after Final is rejected', async () => {
  const key = dstu.secretstreamKeygen();
  const ciphertext = await encryptAll(key, Buffer.from('msg'));
  const withTrailing = Buffer.concat([ciphertext, Buffer.from('unexpected trailing bytes')]);
  await assert.rejects(() => decryptAll(key, withTrailing), /trailing/);
});

test('an error mid-write leaves the stream unfinalized (D-118 pitfall #1)', async () => {
  const key = dstu.secretstreamKeygen();
  const enc = new dstu.SecretStreamEncryptor(key);
  const chunks = [];
  enc.on('data', (c) => chunks.push(c));
  const errored = new Promise((resolve) => enc.on('error', resolve));
  enc.write(Buffer.from('chunk one'));
  enc.destroy(new Error('simulated failure mid-stream'));
  await errored;
  const truncated = Buffer.concat(chunks);
  await assert.rejects(() => decryptAll(key, truncated), /Final/);
});

test('wrong-length key is rejected', () => {
  assert.throws(() => new dstu.SecretStreamPushState(Buffer.from('too short')));
});

test('write after end is rejected', async () => {
  // Node's Writable does not reliably emit a catchable 'error' event for a write-after-end on
  // this stream once it has already auto-destroyed (confirmed by running it with a hard timeout -
  // the 'error' listener never fired, so an earlier version of this test that awaited it hung
  // forever). The actually-documented, synchronous contract is `.writableEnded`/write()'s own
  // return value - assert against that instead of an event that isn't guaranteed to arrive.
  const key = dstu.secretstreamKeygen();
  const enc = new dstu.SecretStreamEncryptor(key);
  enc.resume(); // discard output, avoid backpressure deadlock
  enc.write(Buffer.from('data'));
  enc.end();
  await new Promise((resolve) => enc.on('finish', resolve));
  assert.strictEqual(enc.writableEnded, true);
  assert.strictEqual(enc.write(Buffer.from('more data')), false);
});
