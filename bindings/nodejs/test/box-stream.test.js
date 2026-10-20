'use strict';

/**
 * Streaming `crypto_box`/`crypto_box384`/`crypto_box512` (T-265 format v3, T-269, T-297):
 * `BoxEncryptor`/`BoxDecryptor` and the 384/512 pairs over the core's `seal_stream`/`open_stream`. Happy path: the shared v3 vectors
 * (one-shot `boxOpen` and the streaming reader), a round trip across record boundaries, the
 * one-shot/streaming byte equivalence. Security: tampering, a wrong key, trailing data. Misuse:
 * wrong-length keys, a cut prefix, the 0.4-0.6 format. Error path: a destroyed pipeline leaves no
 * Final record (D-118 pitfall 1). Mirrors bindings/python/tests/test_box_stream.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dstu = require('../js/index.js');

const VECTORS = path.resolve(__dirname, '..', '..', '..', 'crates', 'dstu-core', 'tests', 'vectors', 'box');

const CURVES = {
  256: {
    open: dstu.boxOpen, Enc: dstu.BoxEncryptor, Dec: dstu.BoxDecryptor,
    keygen: dstu.boxKeygen, publicKey: dstu.boxPublicKey, secretField: 'box256_secret_key_hex',
  },
  384: {
    open: dstu.box384Open, Enc: dstu.Box384Encryptor, Dec: dstu.Box384Decryptor,
    keygen: dstu.box384Keygen, publicKey: dstu.box384PublicKey, secretField: 'box384_secret_key_hex',
  },
  512: {
    open: dstu.box512Open, Enc: dstu.Box512Encryptor, Dec: dstu.Box512Decryptor,
    keygen: dstu.box512Keygen, publicKey: dstu.box512PublicKey, secretField: 'box512_secret_key_hex',
  },
};

function pattern(n) {
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + 7) % 256;
  return out;
}

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(VECTORS, name), 'utf8'));
}

/** Same single-consumer helper as secretstream.test.js (see its comment for why). */
async function runThrough(transform, input) {
  const chunks = [];
  const reading = (async () => {
    for await (const c of transform) chunks.push(c);
  })();
  const writing = (async () => {
    for (const piece of input) {
      if (transform.destroyed) return;
      if (!transform.write(piece)) {
        await new Promise((resolve) => {
          transform.once('drain', resolve);
          transform.once('close', resolve);
        });
      }
    }
    if (!transform.destroyed) transform.end();
  })();
  await Promise.all([reading, writing]);
  return Buffer.concat(chunks);
}

for (const curve of [256, 384, 512]) {
  const c = CURVES[curve];

  test(`box${curve}: shared v3 vectors give their expected outcome`, async () => {
    const vectors = load('v3.json');
    const secret = Buffer.from(vectors[c.secretField], 'hex');
    let seen = 0;
    for (const v of vectors.cases.filter((x) => x.curve === curve)) {
      const sealed = Buffer.from(v.sealed_hex, 'hex');
      if (v.expect === 'ok') {
        const expected = pattern(v.plaintext_len);
        assert.deepStrictEqual(c.open(secret, sealed), expected, v.name);
        assert.deepStrictEqual(await runThrough(new c.Dec(secret), [sealed]), expected, v.name);
      } else {
        assert.throws(() => c.open(secret, sealed), undefined, v.name);
        await assert.rejects(runThrough(new c.Dec(secret), [sealed]), undefined, v.name);
      }
      seen++;
    }
    assert.ok(seen > 0);
  });

  test(`box${curve}: the 0.6 format is refused as unsupported`, async () => {
    if (curve === 384) {
      // 0.4-0.6 had no l(p)=384 (T-297): a version-2 byte stands in for such a file.
      const secret = c.keygen();
      const sealed = Buffer.concat([Buffer.from([2]), Buffer.alloc(240)]);
      assert.throws(() => c.open(secret, sealed), /version/);
      await assert.rejects(runThrough(new c.Dec(secret), [sealed]), /version/);
      return;
    }
    const vectors = load('legacy_v2.json');
    const secret = Buffer.from(vectors[c.secretField], 'hex');
    for (const v of vectors.cases.filter((x) => x.curve === curve)) {
      const sealed = Buffer.from(v.sealed_hex, 'hex');
      assert.throws(() => c.open(secret, sealed), /version/);
      await assert.rejects(runThrough(new c.Dec(secret), [sealed]), /version/);
    }
  });

  test(`box${curve}: streaming round trip, read back one-shot and in small pieces`, async () => {
    const secret = c.keygen();
    for (const size of [0, 1, 8 * 1024, 8 * 1024 + 1, 3 * 8 * 1024 + 5]) {
      const message = pattern(size);
      const sealed = await runThrough(new c.Enc(c.publicKey(secret)), [message.subarray(0, 7), message.subarray(7)]);
      assert.deepStrictEqual(c.open(secret, sealed), message);
      const pieces = [];
      for (let i = 0; i < sealed.length; i += 100) pieces.push(sealed.subarray(i, i + 100));
      assert.deepStrictEqual(await runThrough(new c.Dec(secret), pieces), message);
    }
  });

  test(`box${curve}: tampering, a wrong key and trailing data fail closed`, async () => {
    const secret = c.keygen();
    const sealed = await runThrough(new c.Enc(c.publicKey(secret)), [pattern(100)]);
    await assert.rejects(runThrough(new c.Dec(c.keygen()), [sealed]));
    for (const index of [1, sealed.length >> 1, sealed.length - 1]) {
      const bad = Buffer.from(sealed);
      bad[index] ^= 0x01;
      await assert.rejects(runThrough(new c.Dec(secret), [bad]));
    }
    await assert.rejects(runThrough(new c.Dec(secret), [Buffer.concat([sealed, Buffer.from([0])])]));
  });

  test(`box${curve}: misuse is refused`, async () => {
    const secret = c.keygen();
    assert.throws(() => new c.Enc(Buffer.alloc(3, 1)));
    assert.throws(() => new c.Dec(Buffer.alloc(3, 1)));
    const sealed = await runThrough(new c.Enc(c.publicKey(secret)), [pattern(10)]);
    for (const cut of [0, 1, 50]) {
      await assert.rejects(runThrough(new c.Dec(secret), [sealed.subarray(0, cut)]));
    }
  });

  test(`box${curve}: a destroyed writer emits no Final record`, async () => {
    const secret = c.keygen();
    const enc = new c.Enc(c.publicKey(secret));
    const chunks = [];
    enc.on('data', (d) => chunks.push(d));
    enc.on('error', () => {}); // the destroy below is the expected error
    enc.write(pattern(3 * 8 * 1024));
    await new Promise((resolve) => setImmediate(resolve));
    enc.destroy(new Error('upstream failed'));
    await new Promise((resolve) => enc.once('close', resolve));
    await assert.rejects(runThrough(new c.Dec(secret), [Buffer.concat(chunks)]));
  });
}
