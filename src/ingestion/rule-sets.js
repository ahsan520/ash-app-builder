'use strict';
// Builds the compiled rule sets a parser needs from rule SOURCE text, with no database access.
// A worker thread cannot be handed compiled rules (they hold functions), so the API sends the user's rule
// text and the worker compiles it here. The order and the fallback match src/ingestion/rules-store.js:
//   parsing -> [user, built-in]   (first matching rule wins)
//   model   -> [built-in, user]   (additive; later assignments override earlier)
// A broken user ruleset never stops ingestion: it falls back to the built-in rules only.
const { compile } = require('./parsing-rules');

const DEFAULTS = {
  parsing: compile(require('./default-parsing-rules'), 'ingest').rules,
  model: compile(require('./default-model-rules'), 'model').rules,
};

function sets(kind, userSrc) {
  const d = DEFAULTS[kind];
  if (typeof userSrc !== 'string' || !userSrc.trim()) return [d];
  try {
    const user = compile(userSrc, kind === 'parsing' ? 'ingest' : 'model').rules;
    return kind === 'parsing' ? [user, d] : [d, user];
  } catch (e) {
    console.error(`[parser] ${kind} rules did not compile, using the built-in rules:`, e.message);
    return [d];
  }
}

// src = { parsing: '<user parsing rules or empty>', model: '<user model rules or empty>' }
function buildSets(src = {}) {
  return { parsingSets: sets('parsing', src.parsing), modelSets: sets('model', src.model) };
}

module.exports = { buildSets };
