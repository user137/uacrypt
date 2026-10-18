'use strict';

/**
 * `crypto_pwhash` (Argon2id, the one deliberately non-DSTU component, D-49/D-50). Correctness:
 * round trip. Rejection: wrong password, malformed hash string. Misuse: invalid `strength` value.
 * `PWHASH_INTERACTIVE` is used throughout (not the default `PWHASH_MODERATE`) so this file's own
 * tests stay fast. Mirrors bindings/python/tests/test_pwhash.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const dstu = require('../js/index.js');

test('hash/verify round-trips', () => {
  const stored = dstu.pwhashHashPassword(Buffer.from('correct horse battery staple'), dstu.PWHASH_INTERACTIVE);
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('correct horse battery staple'), stored), true);
});

test('wrong password is rejected', () => {
  const stored = dstu.pwhashHashPassword(Buffer.from('correct horse battery staple'), dstu.PWHASH_INTERACTIVE);
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('wrong guess'), stored), false);
});

test('malformed hash string is rejected', () => {
  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('anything'), 'not a real PHC string'), false);
});

test('invalid strength is rejected', () => {
  assert.throws(() => dstu.pwhashHashPassword(Buffer.from('password'), 255));
});

// T-272/D-222: a crafted hash string returns false instead of aborting the Node process.
const VERIFY_VECTORS = path.resolve(__dirname, '..', '..', '..', 'crates', 'dstu-core', 'tests', 'vectors', 'pwhash', 'verify.json');
for (const c of JSON.parse(fs.readFileSync(VERIFY_VECTORS, 'utf8')).cases) {
  test(`shared verify vector: ${c.name}`, () => {
    const password = Buffer.from(c.password);
    assert.strictEqual(dstu.pwhashVerifyPassword(password, c.hash), c.expect === 'accept');
    assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.concat([password, Buffer.from('x')]), c.hash), false);
  });
}

// T-269: pwhashDeriveKey equals libsodium crypto_pwhash (the vectors' oracle, D-219).
const DERIVE_VECTORS = path.resolve(VERIFY_VECTORS, '..', 'derive_key.json');

test('pwhashDeriveKey matches the libsodium vectors', () => {
  const cases = JSON.parse(fs.readFileSync(DERIVE_VECTORS, 'utf8')).cases;
  assert.strictEqual(cases.length, 3);
  for (const c of cases) {
    const key = dstu.pwhashDeriveKey(Buffer.from(c.password_hex, 'hex'), Buffer.from(c.salt_hex, 'hex'), dstu.PWHASH_MODERATE);
    assert.strictEqual(key.toString('hex'), c.key_hex, c.name);
  }
});

test('pwhashDeriveKey refuses a wrong-length salt and an unknown strength', () => {
  assert.throws(() => dstu.pwhashDeriveKey(Buffer.from('pw'), Buffer.alloc(15)), /salt/);
  assert.throws(() => dstu.pwhashDeriveKey(Buffer.from('pw'), Buffer.alloc(16), 255), /strength/);
});
