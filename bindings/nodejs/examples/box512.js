'use strict';

// crypto_box512 (l(p)=512 sibling of crypto_box, T-193/T-204): generate a keypair, seal a message
// to the public key, open it with the secret key.
//
// Run: node examples/box512.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const secretKey = dstu.box512Keygen();
  const publicKey = dstu.box512PublicKey(secretKey); // safe to share/publish

  const message = Buffer.from("a message for the public key's holder only");
  const sealed = dstu.box512Seal(publicKey, message);
  const opened = dstu.box512Open(secretKey, sealed);
  assert.deepStrictEqual(opened, message);
  console.log(`sealed ${message.length} bytes -> ${sealed.length} bytes, round-tripped OK`);

  const tampered = Buffer.from(sealed);
  tampered[tampered.length - 1] ^= 1;
  try {
    dstu.box512Open(secretKey, tampered);
  } catch {
    console.log('tampered ciphertext correctly rejected');
  }
}

main();
