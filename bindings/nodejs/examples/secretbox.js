'use strict';

// crypto_secretbox: seal/open a single message with a symmetric key.
//
// Run: node examples/secretbox.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const key = dstu.secretboxKeygen();
  const sealed = dstu.secretboxSeal(key, Buffer.from('a message worth protecting'));
  const plaintext = dstu.secretboxOpen(key, sealed);
  assert.deepStrictEqual(plaintext, Buffer.from('a message worth protecting'));
  console.log(`sealed ${plaintext.length} bytes -> ${sealed.length} bytes, round-tripped OK`);

  const tampered = Buffer.from(sealed);
  tampered[tampered.length - 1] ^= 1;
  try {
    dstu.secretboxOpen(key, tampered);
  } catch {
    console.log('tampered ciphertext correctly rejected');
  }
}

main();
