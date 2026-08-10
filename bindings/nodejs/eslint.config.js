'use strict';

// T-208: this binding's own linter - plain CommonJS JS (no TypeScript source; native/index.d.ts is
// napi-rs-generated, not hand-written), so @eslint/js's recommended rule set is the whole scope,
// same "no invented custom rules" posture every other binding's own linter/analyzer takes in this
// project. Covers js/ (hand-written wrapper), test/, examples/ - not native/ (napi-rs-generated,
// never hand-edited, gitignored).

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
  },
  {
    ignores: ['native/**', 'node_modules/**'],
  },
];
