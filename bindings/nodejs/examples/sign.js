'use strict';

// crypto_sign (DSTU 4145): generate a signing keypair, sign a message, verify it.
//
// Run: node examples/sign.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const signingKey = dstu.signKeygen();
  const verifyingKey = dstu.signVerifyingKey(signingKey);

  const message = Buffer.from('a message whose origin and integrity matter');
  const signature = dstu.signMessage(signingKey, message);
  assert.strictEqual(dstu.signVerify(verifyingKey, message, signature), true);
  console.log(`signed and verified a ${message.length}-byte message`);

  if (!dstu.signVerify(verifyingKey, Buffer.from('a different message'), signature)) {
    console.log('signature over a different message correctly rejected');
  }
}

main();
