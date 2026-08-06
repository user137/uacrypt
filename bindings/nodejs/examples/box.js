'use strict';

// crypto_box: generate a keypair, seal a message to the public key, open it with the secret key.
//
// Run: node examples/box.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const secretKey = dstu.boxKeygen();
  const publicKey = dstu.boxPublicKey(secretKey); // safe to share/publish

  const message = Buffer.from("a message for the public key's holder only");
  const sealed = dstu.boxSeal(publicKey, message);
  const opened = dstu.boxOpen(secretKey, sealed);
  assert.deepStrictEqual(opened, message);
  console.log(`sealed ${message.length} bytes -> ${sealed.length} bytes, round-tripped OK`);

  const tampered = Buffer.from(sealed);
  tampered[tampered.length - 1] ^= 1;
  try {
    dstu.boxOpen(secretKey, tampered);
  } catch {
    console.log('tampered ciphertext correctly rejected');
  }
}

main();
