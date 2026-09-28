"""Static QA and synthetic selector tests; not a Sigma engine or SIEM replay."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
import yaml

ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = {'process_creation': 1, 'file_event': 11, 'network_connection': 3}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def matches(rule, event):
    """Only the exact selector subset in the supplied three rules is supported."""
    check(rule['logsource']['product'] == 'windows', 'Unsupported product')
    category = rule['logsource']['category']
    check(category in CATEGORIES, 'Unsupported category')
    if event.get('EventID') != CATEGORIES[category]:
        return False
    detection = rule['detection']
    condition = detection['condition']
    check(re.fullmatch(r'selection(?:_\w+)?(?: and selection(?:_\w+)?)*', condition),
          'Unsupported condition')
    results = []
    for name in condition.split(' and '):
        selection = detection[name]
        selected = []
        for key, expected in selection.items():
            parts = key.split('|')
            check(len(parts) <= 2, 'Unsupported modifiers')
            field, modifier = parts[0], parts[1] if len(parts) == 2 else 'equals'
            check(modifier in ('equals', 'endswith', 'contains'), 'Unsupported modifier')
            choices = expected if isinstance(expected, list) else [expected]
            check(all(isinstance(v, str) for v in choices), 'Only literal string selectors supported')
            actual = event.get(field)
            if not isinstance(actual, str):
                selected.append(False)
                continue
            actual = actual.casefold()
            hit = False
            for value in choices:
                check(not any(c in value for c in '*?'), 'Wildcards not implemented')
                value = value.casefold()
                hit |= (actual == value if modifier == 'equals' else
                        actual.endswith(value) if modifier == 'endswith' else value in actual)
            selected.append(hit)
        results.append(all(selected))
    return all(results)


def main():
    print('LOCAL STATIC AND SYNTHETIC QA — NOT SIGMA-ENGINE EXECUTION')
    print('Python:', sys.version.split()[0], '| PyYAML:', yaml.__version__)
    rules = {}
    ids = set()
    required = {'title', 'id', 'status', 'description', 'author', 'date', 'logsource', 'detection', 'level'}
    for file in sorted((ROOT / 'detections').glob('*.yml')):
        rule = yaml.safe_load(file.read_text())
        check(isinstance(rule, dict) and required <= rule.keys(), f'{file.name}: missing core fields')
        uid = str(uuid.UUID(rule['id']))
        check(uid not in ids, 'Duplicate UUID')
        ids.add(uid)
        check(rule['status'] == 'experimental', 'Unexpected rule status')
        check(isinstance(rule['date'], (datetime.date, str)), 'Invalid date representation')
        rules[file.stem] = rule
        print('PASS YAML/core fields/UUID:', file.name)
    check(len(rules) == 3, 'Expected three rules')
    config = ET.parse(ROOT / 'config/sysmon-lab-config.xml').getroot()
    check(config.tag == 'Sysmon' and config.attrib.get('schemaversion') == '4.91', 'XML schema attribute')
    check(config.findtext('HashAlgorithms') == 'sha256', 'Expected SHA256')
    sections = list(config.find('EventFiltering'))
    check({s.tag for s in sections} == {'ProcessCreate', 'NetworkConnect', 'FileCreate', 'DnsQuery'}, 'Collection categories')
    check(all(s.attrib == {'onmatch': 'exclude'} and len(s) == 0 for s in sections), 'Expected broad empty exclusions')
    print('PASS XML structure (not live Sysmon acceptance)')
    fixtures = json.loads((ROOT / 'validation/synthetic-cases.json').read_text())
    for case in fixtures:
        result = matches(rules[case['rule']], case['event'])
        check(result == case['expected'], f"{case['name']}: expected {case['expected']}, got {result}")
        print(f"PASS synthetic selector case: {case['name']} -> {result}")
    manifest = json.loads((ROOT / 'evidence/source-manifest.json').read_text())
    for artifact in [manifest['source_pdf']] + manifest['figures']:
        raw = (ROOT / artifact['path']).read_bytes()
        check(hashlib.sha256(raw).hexdigest() == artifact['sha256'], 'Source integrity: ' + artifact['path'])
    print('PASS original PDF and 15 extracted-image hashes')
    for file in ROOT.rglob('*.md'):
        for target in re.findall(r'\]\(([^)]+)\)', file.read_text()):
            if '://' not in target and not target.startswith('#'):
                check((file.parent / target.split('#')[0]).exists(), f'Broken local link: {file.name}: {target}')
    print('PASS local Markdown file links')
    print(f'PASS: 3 rule files; 1 XML config; {len(fixtures)} synthetic cases; source integrity; document links')
    print('Not performed: Windows execution, Sigma semantic/backend validation, SIEM alerts, production measurement.')


if __name__ == '__main__':
    main()
