#!/usr/bin/env python3
"""Makes the few changes ASIX needs in a Wazuh manager's ossec.conf, and nothing else (docs/endpoints.md, task E4b).

  ossec-edit.py FILE            edit FILE in place (writes only when something changed)
  ossec-edit.py FILE --check    only report what would change
  ossec-edit.py FILE --indexer-url https://HOST:PORT --indexer-ca /path/root-ca.pem [--check]
                                switch vulnerability detection ON and point the manager at a Wazuh indexer (task E6g) instead of switching it off

The changes:
  global       <logall_json>yes</logall_json>          REQUIRED: without it the manager does not write archives.json, which the broker reads
  auth         <use_password>yes</use_password>         REQUIRED: an agent must know the enrolment password (etc/authd.pass) to register
  vulnerability-detection   <enabled>no</enabled>      optional: it needs the Wazuh indexer, which a broker VM does not run
  indexer      <enabled>no</enabled>                   optional: same reason
With --indexer-url and --indexer-ca (the user name and password are NOT in ossec.conf: they go in the manager's keystore):
  vulnerability-detection  <enabled>yes</enabled> and <index-status>yes</index-status>
  indexer      <enabled>yes</enabled>, <hosts><host>URL</host>, <ssl><certificate_authorities><ca>PATH</ca>; a <certificate> and a <key> line left by the
               package (they point at Filebeat files that do not exist on a manager without one) are removed: the manager signs in with its user and password.
               Every one of these is REQUIRED in this mode: a missing block is exit 3 and nothing is written.

ossec.conf is not one XML document (it has several <ossec_config> blocks), so it is edited as text. Comments are masked first, so a
commented-out block is never edited, and everything outside the changed lines stays byte for byte as it was. Running it twice changes
nothing the second time. Standard library only, so it runs on the Python that ships with Wazuh as well as on the system one.
Prints one line per change: "<name>: applied|unchanged|missing". Exit 0 when the required changes are in place, 3 when one could not be made.
"""
import re
import sys


def mask(text):
    """The text with every comment blanked out (same length, same newlines), to search in."""
    return re.sub(r'<!--.*?-->', lambda m: re.sub(r'[^\n]', ' ', m.group(0)), text, flags=re.S)


def block(masked, tag, lo=0, hi=None):
    """(start, end) of the inside of the first <tag>...</tag> in the masked text (between lo and hi), or None.
    tag may be a path such as 'indexer/ssl': each part is looked for inside the previous one."""
    hi = len(masked) if hi is None else hi
    parts = tag.split('/')
    if len(parts) > 1:
        for part in parts:
            b = block(masked, part, lo, hi)
            if b is None:
                return None
            lo, hi = b
        return (lo, hi)
    m = re.compile(r'<%s(?:\s[^>]*)?>' % re.escape(tag)).search(masked, lo, hi)
    if not m:
        return None
    e = masked.find('</%s>' % tag, m.end(), hi)
    return None if e < 0 else (m.end(), e)


def set_value(text, tag, child, value, create):
    """Set <child> inside the first <tag> block to value. Returns (new_text, 'applied'|'unchanged'|'missing')."""
    masked = mask(text)
    b = block(masked, tag)
    if b is None:
        return text, 'missing'
    inner = masked[b[0]:b[1]]
    m = re.search(r'<%s>([^<]*)</%s>' % (re.escape(child), re.escape(child)), inner)
    if m:
        if m.group(1).strip() == value:
            return text, 'unchanged'
        s, e = b[0] + m.start(1), b[0] + m.end(1)
        return text[:s] + value + text[e:], 'applied'
    if not create:
        return text, 'missing'
    # a new line right after the opening tag, indented like the block's first child
    open_end = b[0]
    first = re.search(r'\n([ \t]*)<', text[open_end:b[1]])
    indent = first.group(1) if first else '    '
    return text[:open_end] + '\n%s<%s>%s</%s>' % (indent, child, value, child) + text[open_end:], 'applied'


def remove_value(text, tag, child):
    """Remove the whole line of <child>...</child> inside the first <tag> block (a path is allowed). Returns (new_text, 'applied'|'unchanged'|'missing')."""
    masked = mask(text)
    b = block(masked, tag)
    if b is None:
        return text, 'missing'
    m = re.search(r'\n?[ \t]*<%s>[^<]*</%s>[ \t]*(?=\n|$)' % (re.escape(child), re.escape(child)), masked[b[0]:b[1]])
    if not m:
        return text, 'unchanged'
    return text[:b[0] + m.start()] + text[b[0] + m.end():], 'applied'


URL_RE = re.compile(r'^https://[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?$')
PATH_RE = re.compile(r'^/[A-Za-z0-9._/\-]{1,200}$')


def indexer_edits(url, ca):
    """The edits of indexer mode: (name, kind, tag, child, value, create). Every one is required."""
    return [
        ('vulnerability-detection/enabled', 'set', 'vulnerability-detection', 'enabled', 'yes', False),
        ('vulnerability-detection/index-status', 'set', 'vulnerability-detection', 'index-status', 'yes', True),
        ('indexer/enabled', 'set', 'indexer', 'enabled', 'yes', False),
        ('indexer/hosts/host', 'set', 'indexer/hosts', 'host', url, False),
        ('indexer/ssl/ca', 'set', 'indexer/ssl/certificate_authorities', 'ca', ca, False),
        ('indexer/ssl/certificate', 'remove', 'indexer/ssl', 'certificate', None, False),
        ('indexer/ssl/key', 'remove', 'indexer/ssl', 'key', None, False),
    ]


EDITS = [
    # name, tag, child, value, create the child when missing, required
    ('global/logall_json', 'global', 'logall_json', 'yes', True, True),
    ('auth/use_password', 'auth', 'use_password', 'yes', True, True),
    ('vulnerability-detection/enabled', 'vulnerability-detection', 'enabled', 'no', False, False),
    ('indexer/enabled', 'indexer', 'enabled', 'no', False, False),
]


def run(text, indexer=None):
    """indexer is None (detection off, the default) or (url, ca_path) (detection on, E6g)."""
    out, results, failed = text, [], False
    for name, tag, child, value, create, required in EDITS:
        if indexer and tag in ('vulnerability-detection', 'indexer'):
            continue   # decided below, the other way round
        out, status = set_value(out, tag, child, value, create)
        results.append((name, status))
        if status == 'missing' and required:
            failed = True
    if indexer:
        for name, kind, tag, child, value, create in indexer_edits(*indexer):
            if kind == 'set':
                out, status = set_value(out, tag, child, value, create)
            else:
                out, status = remove_value(out, tag, child)
            results.append((name, status))
            if status == 'missing':
                failed = True
    return out, results, failed


def main(argv):
    if len(argv) < 2 or argv[1].startswith('-'):
        sys.stderr.write(__doc__)
        return 2
    path, rest = argv[1], argv[2:]
    check = '--check' in rest
    opts = {}
    for i, a in enumerate(rest):
        if a in ('--indexer-url', '--indexer-ca'):
            if i + 1 >= len(rest):
                sys.stderr.write('%s needs a value.\n' % a)
                return 2
            opts[a] = rest[i + 1]
    unknown = [a for i, a in enumerate(rest) if a not in ('--check', '--indexer-url', '--indexer-ca') and not (i > 0 and rest[i - 1] in ('--indexer-url', '--indexer-ca'))]
    if unknown:
        sys.stderr.write('Unknown option: %s\n' % unknown[0])
        return 2
    indexer = None
    if opts:
        if len(opts) != 2:
            sys.stderr.write('--indexer-url and --indexer-ca go together.\n')
            return 2
        url, ca = opts['--indexer-url'], opts['--indexer-ca']
        if not URL_RE.match(url):
            sys.stderr.write('--indexer-url must be https://host or https://host:port (letters, digits, dots, dashes).\n')
            return 2
        if not PATH_RE.match(ca) or '..' in ca:
            sys.stderr.write('--indexer-ca must be an absolute path of plain characters (letters, digits, . _ - /).\n')
            return 2
        indexer = (url, ca)
    with open(path, encoding='utf-8') as f:
        text = f.read()
    out, results, failed = run(text, indexer)
    for name, status in results:
        print('%s: %s' % (name, status))
    if failed:
        sys.stderr.write('A required setting could not be found in %s (no <global> or <auth> block%s): nothing was written. Make the changes by hand.\n' % (path, ', or a missing vulnerability-detection or indexer block' if indexer else ''))
        return 3
    if out != text and not check:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
