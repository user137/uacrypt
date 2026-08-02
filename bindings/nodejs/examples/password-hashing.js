'use strict';

// crypto_pwhash (Argon2id): hash and verify a password.
//
// PWHASH_INTERACTIVE is used here so the example runs fast - PWHASH_MODERATE (the default
// strength most applications should use) and PWHASH_SENSITIVE both take real seconds by design.
//
// Run: node examples/password-hashing.js

const assert = require('node:assert/strict');
const dstu = require('../js/index.js');

function main() {
  const password = Buffer.from('correct horse battery staple');
  const stored = dstu.pwhashHashPassword(password, dstu.PWHASH_INTERACTIVE);
  console.log(`stored hash: ${stored}`);

  assert.strictEqual(dstu.pwhashVerifyPassword(password, stored), true);
  console.log('correct password accepted');

  assert.strictEqual(dstu.pwhashVerifyPassword(Buffer.from('wrong guess'), stored), false);
  console.log('wrong password correctly rejected');
}

main();
