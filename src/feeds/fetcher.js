'use strict';
// Fetching an indicator feed over HTTP (task: IOC feed import, docs/ioc-feeds.md). The address comes from a tenant, so this is where a server-side request
// forgery would happen; the rules are strict and live in one place:
//  - http and https only, no user name or password in the address;
//  - the name is resolved HERE and the connection is made to the address that was checked (a `lookup` handed to the socket), so a name that answers with
//    a harmless address first and an internal one second cannot slip through (DNS rebinding);
//  - loopback, private, link-local (which includes the cloud metadata address), shared (100.64/10), multicast and reserved addresses are refused, for the first
//    request and for every redirect, unless ASIX_FEED_ALLOW_PRIVATE=1 (a feed server inside the network; off by default);
//  - at most 3 redirects, each checked again; a token (Authorization) is sent only to the address that was asked for, never to a redirect target on another host;
//  - a time limit for the whole request and a size limit for the body, so a slow or endless answer cannot hold the worker;
//  - errors name the host and path, never the query string (a feed address can carry a key in it).
const http = require('http');
const https = require('https');
const dns = require('dns');
const net = require('net');

const LIMITS = { timeoutMs: 20000, maxBytes: 5 * 1024 * 1024, maxRedirects: 3 };

const blocked = new net.BlockList();
for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4]]) blocked.addSubnet(a, p, 'ipv4');
for (const [a, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96]]) blocked.addSubnet(a, p, 'ipv6');

// true when a connection to this address must be refused
function isBlockedAddress(ip) {
  const fam = net.isIP(ip);
  if (!fam) return true;
  if (fam === 6) {
    const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);   // an IPv4 address written as IPv6 is judged as IPv4
    if (m) return blocked.check(m[1], 'ipv4');
    const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
    if (hex) { const n = (parseInt(hex[1], 16) << 16) | parseInt(hex[2], 16); return blocked.check([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'), 'ipv4'); }
    return blocked.check(ip, 'ipv6');
  }
  return blocked.check(ip, 'ipv4');
}

const fail = (code, message) => Object.assign(new Error(message), { code });
const allowPrivate = () => process.env.ASIX_FEED_ALLOW_PRIVATE === '1';
const safeName = (u) => `${u.protocol}//${u.host}${u.pathname.length > 60 ? u.pathname.slice(0, 60) + '…' : u.pathname}`;   // never the query

function parseUrl(text) {
  let u; try { u = new URL(text); } catch { throw fail('BAD_URL', 'The feed address is not a valid address'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw fail('BAD_URL', 'The feed address must start with http:// or https://');
  if (u.username || u.password) throw fail('BAD_URL', 'The feed address must not contain a user name or password');
  return u;
}

// dns.lookup replacement for the socket: resolves, refuses when ANY answer is blocked, and hands back the first (checked) address.
function checkedLookup(hostname, options, cb) {
  dns.lookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(fail('DNS_FAILED', `The name ${hostname} could not be resolved`));
    if (!allowPrivate() && addrs.some((a) => isBlockedAddress(a.address))) return cb(fail('BLOCKED_ADDRESS', `${hostname} points to an internal or reserved address, which feeds may not use`));
    const a = addrs[0];
    return options && options.all ? cb(null, [a]) : cb(null, a.address, a.family);
  });
}

function once(u, headers, opts) {
  return new Promise((resolve, reject) => {
    if (net.isIP(u.hostname.replace(/^\[|\]$/g, '')) && !allowPrivate() && isBlockedAddress(u.hostname.replace(/^\[|\]$/g, ''))) return reject(fail('BLOCKED_ADDRESS', 'That address is internal or reserved, which feeds may not use'));
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: 'GET', headers, lookup: checkedLookup, timeout: opts.timeoutMs }, (res) => {
      const status = res.statusCode;
      if (status >= 300 && status < 400 && res.headers.location) { res.resume(); return resolve({ redirect: res.headers.location }); }
      if (status !== 200) { res.resume(); return reject(fail('HTTP_STATUS', `The feed answered with status ${status}`)); }
      const declared = Number(res.headers['content-length']);
      if (declared > opts.maxBytes) { res.destroy(); return reject(fail('TOO_LARGE', `The feed is larger than ${opts.maxBytes / 1048576} MB`)); }
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > opts.maxBytes) { res.destroy(); reject(fail('TOO_LARGE', `The feed is larger than ${opts.maxBytes / 1048576} MB`)); } else chunks.push(c); });
      res.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8'), bytes: size }));
      res.on('error', (e) => reject(fail(e.code || 'FETCH_FAILED', 'The feed connection broke')));
    });
    req.on('timeout', () => { req.destroy(); reject(fail('TIMEOUT', 'The feed did not answer in time')); });
    req.on('error', (e) => reject(e.code && /^[A-Z_]+$/.test(e.code) && e.message && !e.syscall ? e : fail(e.code === 'ECONNREFUSED' ? 'CONNECTION_REFUSED' : 'FETCH_FAILED', `Could not reach ${safeName(u)}`)));
    req.end();
  });
}

// -> { body, bytes }. Throws an Error with a `code` and a message that is safe to show.
async function fetchFeed(urlText, { token, timeoutMs = LIMITS.timeoutMs, maxBytes = LIMITS.maxBytes, maxRedirects = LIMITS.maxRedirects } = {}) {
  const deadline = Date.now() + timeoutMs;
  let u = parseUrl(urlText); const origin = u.origin;
  for (let hops = 0; ; hops++) {
    const left = deadline - Date.now(); if (left <= 0) throw fail('TIMEOUT', 'The feed did not answer in time');
    const headers = { 'User-Agent': 'ASIX-feed-import/1', Accept: 'text/plain, text/csv, application/json, */*', 'Accept-Encoding': 'identity' };
    if (token && u.origin === origin) headers.Authorization = `Bearer ${token}`;
    const r = await once(u, headers, { timeoutMs: left, maxBytes });
    if (!r.redirect) return r;
    if (hops >= maxRedirects) throw fail('TOO_MANY_REDIRECTS', 'The feed redirected too many times');
    let next; try { next = new URL(r.redirect, u); } catch { throw fail('BAD_URL', 'The feed redirected to an invalid address'); }
    u = parseUrl(next.href);
  }
}

module.exports = { fetchFeed, isBlockedAddress, parseUrl, LIMITS };
