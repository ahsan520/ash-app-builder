#!/usr/bin/env python3
"""Makes the few changes ASIX needs in a Wazuh manager's ossec.conf, and nothing else (docs/endpoints.md, task E4b).

  ossec-edit.py FILE            edit FILE in place (writes only when something changed)
  ossec-edit.py FILE --check    only report what would change

The changes:
  global       <logall_json>yes</logall_json>          REQUIRED: without it the manager does not write archives.json, which the broker reads
  auth         <use_password>yes</use_password>         REQUIRED: an agent must know the enrolment password (etc/authd.pass) to register
  vulnerability-detection   <enabled>no</enabled>      optional: it needs the Wazuh indexer, which a broker VM does not run
  indexer      <enabled>no</enabled>                   optional: same reason

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


def block(masked, tag):
    """(start, end) of the inside of the first <tag>...</tag> in the masked text, or None."""
    m = re.search(r'<%s(?:\s[^>]*)?>' % re.escape(tag), masked)
    if not m:
        return None
    e = masked.find('</%s>' % tag, m.end())
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


EDITS = [
    # name, tag, child, value, create the child when missing, required
    ('global/logall_json', 'global', 'logall_json', 'yes', True, True),
    ('auth/use_password', 'auth', 'use_password', 'yes', True, True),
    ('vulnerability-detection/enabled', 'vulnerability-detection', 'enabled', 'no', False, False),
    ('indexer/enabled', 'indexer', 'enabled', 'no', False, False),
]


def run(text):
    out, results, failed = text, [], False
    for name, tag, child, value, create, required in EDITS:
        out, status = set_value(out, tag, child, value, create)
        results.append((name, status))
        if status == 'missing' and required:
            failed = True
    return out, results, failed


def main(argv):
    if len(argv) < 2 or argv[1].startswith('-'):
        sys.stderr.write(__doc__)
        return 2
    path, check = argv[1], '--check' in argv[2:]
    with open(path, encoding='utf-8') as f:
        text = f.read()
    out, results, failed = run(text)
    for name, status in results:
        print('%s: %s' % (name, status))
    if failed:
        sys.stderr.write('A required setting could not be found in %s (no <global> or <auth> block): nothing was written. Make the two changes by hand.\n' % path)
        return 3
    if out != text and not check:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
