'use strict';

/**
 * `crypto_kdf` - no official vector exists for this construction (D-45: no DSTU KDF standard or
 * reference implementation exists at all). Correctness here means determinism/distinctness,
 * matching the Rust crate's own property-test posture. Misuse: wrong-length master key/context,
 * negative subkeyId (this binding's own JS-boundary check, D-126 - no rejection category, there
 * is no tag to tamper with). Mirrors bindings/python/tests/test_kdf.py.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

test('deriveSubkey is deterministic', () => {
  const masterKey = dstu.kdfKeygen();
  assert.deepStrictEqual(
    dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('encrypt_')),
    dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('encrypt_')),
  );
});

test('different subkeyId gives a different subkey', () => {
  const masterKey = dstu.kdfKeygen();
  const a = dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('context1'));
  const b = dstu.kdfDeriveSubkey(masterKey, 1, Buffer.from('context1'));
  assert.notDeepStrictEqual(a, b);
});

test('different context gives a different subkey', () => {
  const masterKey = dstu.kdfKeygen();
  const a = dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('context1'));
  const b = dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('context2'));
  assert.notDeepStrictEqual(a, b);
});

test('wrong-length master key is rejected', () => {
  assert.throws(() => dstu.kdfDeriveSubkey(Buffer.from('too short'), 0, Buffer.from('context1')));
});

test('wrong-length context is rejected', () => {
  const masterKey = dstu.kdfKeygen();
  assert.throws(() => dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('short')));
});

test('negative subkeyId is rejected', () => {
  const masterKey = dstu.kdfKeygen();
  assert.throws(() => dstu.kdfDeriveSubkey(masterKey, -1, Buffer.from('context1')));
});
