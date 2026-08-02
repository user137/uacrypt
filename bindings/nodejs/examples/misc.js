'use strict';

// The remaining crypto_* modules, each small enough to share one file:
//
// - crypto_auth (Kupyna-KMAC): keyed message authentication.
// - crypto_kdf: deterministic subkey derivation from a master key.
// - crypto_generichash (Kupyna-256/512): one-shot and streaming hashing.
// - crypto_stream (Strumok-256): unauthenticated keystream cipher - no integrity, wrong key/
//   tampered ciphertext silently decrypts to different, wrong plaintext instead of throwing.
// - randombytes: CSPRNG-backed random bytes.
//
// Run: node examples/misc.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function authExample() {
  const key = dstu.authKeygen();
  const message = Buffer.from('a message both parties want to confirm is unmodified');
  const tag = dstu.auth(key, message);
  dstu.authVerify(key, message, tag);
  console.log('auth: tag verified');
}

function kdfExample() {
  const masterKey = dstu.kdfKeygen();
  const subkeyA = dstu.kdfDeriveSubkey(masterKey, 0, Buffer.from('encrypt_'));
  const subkeyB = dstu.kdfDeriveSubkey(masterKey, 1, Buffer.from('encrypt_'));
  assert.notDeepStrictEqual(subkeyA, subkeyB);
  console.log('kdf: subkey 0 and subkey 1 differ, as expected');
}

function generichashExample() {
  const oneShot = dstu.kupyna256(Buffer.from('hello world'));
  const hasher = new dstu.Kupyna256Hasher();
  hasher.update(Buffer.from('hello '));
  hasher.update(Buffer.from('world'));
  assert.deepStrictEqual(hasher.finalize(), oneShot);
  console.log(`generichash: kupyna256('hello world') = ${oneShot.toString('hex')}`);
}

function streamExample() {
  const key = dstu.streamKeygen();
  const sealed = dstu.streamEncrypt(key, Buffer.from('a message'));
  assert.deepStrictEqual(dstu.streamDecrypt(key, sealed), Buffer.from('a message'));
  console.log('stream: round-tripped (note: unauthenticated, no tamper detection)');
}

function randombytesExample() {
  const a = dstu.randombytesBuf(16);
  const b = dstu.randombytesBuf(16);
  assert.notDeepStrictEqual(a, b);
  console.log(`randombytes: two independent 16-byte draws, e.g. ${a.toString('hex')}`);
}

authExample();
kdfExample();
generichashExample();
streamExample();
randombytesExample();
