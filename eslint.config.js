'use strict';
// Used by CI only (`npm run lint`): catches undefined names such as a route file that forgot a require().
// Run with `npx eslint@9` - eslint is deliberately not a dependency of the platform itself.
const nodeGlobals = Object.fromEntries([
  'require', 'module', 'exports', '__dirname', '__filename', 'process', 'console', 'Buffer', 'global', 'globalThis',
  'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'setImmediate', 'clearImmediate', 'queueMicrotask',
  'URL', 'URLSearchParams', 'TextEncoder', 'TextDecoder', 'AbortController', 'AbortSignal', 'fetch', 'Headers',
  'Request', 'Response', 'FormData', 'Blob', 'structuredClone', 'performance', 'atob', 'btoa', 'crypto',
].map((n) => [n, 'readonly']));

module.exports = [
  { ignores: ['node_modules/**', 'src/portal/**', 'ui/**'] },
  { files: ['**/*.js'], languageOptions: { sourceType: 'commonjs', ecmaVersion: 2022, globals: nodeGlobals }, rules: { 'no-undef': 'error' } },
];
