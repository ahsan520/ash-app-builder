'use strict';
// S3 of docs/product-plan.md ("Status of Phase 5"), contract in docs/portal-shell.md.
// Three small pieces the gateway mounts around the portal:
//   portalHeaders  - the headers for everything under /portal (the shell, and the module page files it loads)
//   moduleFiles    - serves ONLY plain page files from src/portal/modules/<module id>/ (nothing else in that folder)
//   appHeaders     - the headers for /app/* (the open-source tools shown inside the portal, added by S4)
const express = require('express');

// The portal may frame only its own origin (the /app/* tools); nothing may frame the portal.
const PORTAL_CSP =
  "default-src 'self'; connect-src 'self' https:; style-src 'self' 'unsafe-inline'; " +
  "script-src 'self' 'unsafe-inline'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'";

// An embedded tool's pages may be framed by the portal (same origin) and by nobody else.
// Deliberately no default-src or script-src here: the tool needs its own scripts and styles to run. S4 must remove
// any frame-ancestors / X-Frame-Options the tool sends itself, because when two policies apply the browser enforces both.
const APP_CSP = "frame-ancestors 'self'";

function portalHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy': PORTAL_CSP,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  next();
}

function appHeaders(req, res, next) {
  res.set({
    'Content-Security-Policy': APP_CSP,
    'X-Frame-Options': 'SAMEORIGIN',   // older browsers that ignore frame-ancestors
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  next();
}

// Mounted at /portal/modules, so req.path is "/<module id>/<file>". Only that exact shape, with a .js or .css file name, is served.
// The match is on the raw path, so anything encoded (%2e%2e, %2f), nested deeper, hidden (.env), a source map or a note (.md) is a 404.
// This handler answers every request itself, so a refused path never falls through to the general /portal static folder.
const MODULE_FILE = /^\/[a-z][a-z0-9-]*\/[a-z0-9][a-z0-9-]*\.(?:js|css)$/;

function moduleFiles(dir) {
  const serve = express.static(dir, { index: false, dotfiles: 'ignore', redirect: false, fallthrough: true });
  return (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.set('Allow', 'GET, HEAD');
      return res.status(405).type('text/plain').send('Method not allowed');
    }
    if (!MODULE_FILE.test(req.path)) return res.status(404).type('text/plain').send('Not found');
    return serve(req, res, (err) => {
      if (err) return next(err);
      return res.status(404).type('text/plain').send('Not found');   // well-formed name, no such file
    });
  };
}

module.exports = { PORTAL_CSP, APP_CSP, portalHeaders, appHeaders, moduleFiles, MODULE_FILE };
