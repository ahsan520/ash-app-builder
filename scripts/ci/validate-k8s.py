#!/usr/bin/env python3
"""Checks every manifest in k8s/ against the Kubernetes API schema, and the ClickHouse config embedded in k8s/11-clickhouse.yaml
for well-formed XML. Used by CI (job k8s-manifests); also runnable by hand:
    pip install kubernetes-validate pyyaml && python3 scripts/ci/validate-k8s.py [kubernetes-version]
It cannot tell whether a cluster will accept the objects (no cluster here): it catches typos, wrong field names and wrong types.
"""
import glob, re, sys, xml.etree.ElementTree as ET
import yaml, kubernetes_validate

version = sys.argv[1] if len(sys.argv) > 1 else '1.30'
failures = 0

def docs(path):
    text = open(path).read()
    if path.endswith('20-keycloak.yaml'):
        # deploy.sh feeds this file through awk '/^---/{found=1} found': everything before the first --- is a comment block.
        text = text[text.index('\n---') + 1:] if '\n---' in text else text
    return [d for d in yaml.safe_load_all(text) if d]

for path in sorted(glob.glob('k8s/*.yaml')):
    try:
        items = docs(path)
    except yaml.YAMLError as e:
        failures += 1; print(f'FAIL {path}: not YAML: {str(e)[:200]}'); continue
    for d in items:
        name = f"{d.get('kind')}/{d.get('metadata', {}).get('name')}"
        try:
            kubernetes_validate.validate(d, version, strict=True)
            print(f'ok   {path}: {name}')
        except Exception as e:
            failures += 1; print(f'FAIL {path}: {name}: {str(e).splitlines()[0][:200]}')
        if d.get('kind') == 'ConfigMap':
            for key, value in (d.get('data') or {}).items():
                if key.endswith('.xml'):
                    try: ET.fromstring(value); print(f'ok   {path}: {name}[{key}] is well-formed XML')
                    except ET.ParseError as e: failures += 1; print(f'FAIL {path}: {name}[{key}]: {e}')

# The API must be able to reach the ClickHouse it is deployed next to: same service name, port, database and user.
api = open('k8s/30-asix-api.yaml').read(); ch = open('k8s/11-clickhouse.yaml').read()
m = re.search(r'ASIX_CLICKHOUSE_URL\n\s+value: "http://(\w+):\$\(CLICKHOUSE_PASSWORD\)@([\w.-]+):(\d+)/(\w+)"', api)
if not m: failures += 1; print('FAIL k8s/30-asix-api.yaml: ASIX_CLICKHOUSE_URL not in the expected form')
else:
    user, host, port, db = m.groups()
    for what, ok in [('service name', re.search(rf'kind: Service\nmetadata:\n  name: {host}\n', ch)), ('port', re.search(rf'port: {port}\n', ch)),
                     ('user', re.search(rf'CLICKHOUSE_USER\n\s+value: "{user}"', ch)), ('database', re.search(rf'CLICKHOUSE_DB\n\s+value: "{db}"', ch))]:
        if ok: print(f'ok   API URL and k8s/11-clickhouse.yaml agree on the {what}')
        else: failures += 1; print(f'FAIL API URL and k8s/11-clickhouse.yaml disagree on the {what}')

print('failures:', failures)
sys.exit(1 if failures else 0)
