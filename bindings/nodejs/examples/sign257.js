'use strict';

// crypto_sign257 (DSTU 4145 m=257, T-199/T-204): generate a signing keypair, sign a message,
// verify it.
//
// Run: node examples/sign257.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const signingKey = dstu.sign257Keygen();
  const verifyingKey = dstu.sign257VerifyingKey(signingKey);

  const message = Buffer.from('a message whose origin and integrity matter');
  const signature = dstu.sign257Message(signingKey, message);
  assert.strictEqual(dstu.sign257Verify(verifyingKey, message, signature), true);
  console.log(`signed and verified a ${message.length}-byte message`);

  if (!dstu.sign257Verify(verifyingKey, Buffer.from('a different message'), signature)) {
    console.log('signature over a different message correctly rejected');
  }
}

main();
