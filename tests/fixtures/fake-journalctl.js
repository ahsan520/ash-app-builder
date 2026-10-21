#!/usr/bin/env node
'use strict';
// A stand-in for `journalctl`, for tests/broker-journald.test.js (a CI runner and most dev machines have no journal Vector may read).
// Vector's journald source runs `journalctl --follow --all --show-cursor --output=json [--since=now | --after-cursor=C]` and reads one JSON
// object per line. This does the same from a file the test appends to:
//   FAKE_JOURNAL_DIR/journal.jsonl   one journal entry (JSON, with its own "__CURSOR") per line
//   FAKE_JOURNAL_DIR/argv.log        every call's arguments, one line per call (the test reads which start point Vector asked for)
// --version answers like systemd. --since=now starts at the end of the file; --after-cursor=C starts after the entry whose __CURSOR is C;
// anything else starts at the beginning. Then it prints every line appended later, until it is killed.
const fs = require('fs');
const path = require('path');

const dir = process.env.FAKE_JOURNAL_DIR;
const args = process.argv.slice(2);
if (dir) fs.appendFileSync(path.join(dir, 'argv.log'), args.join(' ') + '\n');
if (args[0] === '--version') { process.stdout.write('systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT +SELINUX\n'); process.exit(0); }
if (!dir) { process.stderr.write('FAKE_JOURNAL_DIR is not set\n'); process.exit(1); }

const file = path.join(dir, 'journal.jsonl');
if (!fs.existsSync(file)) fs.writeFileSync(file, '');
const after = (args.find((a) => a.startsWith('--after-cursor=')) || '').slice('--after-cursor='.length);
const lines = () => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);

let next = 0;   // index of the next line to print
if (args.includes('--since=now')) next = lines().length;
if (after) { const i = lines().findIndex((l) => { try { return JSON.parse(l).__CURSOR === after; } catch { return false; } }); next = i >= 0 ? i + 1 : 0; }

const tick = () => { const all = lines(); while (next < all.length) process.stdout.write(all[next++] + '\n'); };
tick(); setInterval(tick, 100);
process.on('SIGTERM', () => process.exit(0));
process.stdout.on('error', () => process.exit(0));
