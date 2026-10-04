#!/usr/bin/env python3
"""Fail closed on selector widening, empty cases and zero relevant assertions."""
import json
import re
import sys
from pathlib import Path

CATALOG = {
    'testGateway_discovery': 6,
    'testGateway_validation': 5,
    'testIdentity_credentials': 4,
    'testDurability_run_restart': 6,
    'testState_namespace': 7,
}

def selection(args):
    modules = ['test']
    tags = []
    for arg in args:
        if arg.startswith('-t='):
            modules = arg[3:].split(',')
        elif arg.startswith('-i='):
            tags = arg[3:].split(',')
    allowed = {'test'} | {tag.split('_')[0] for tag in CATALOG}
    if any(module not in allowed for module in modules):
        raise ValueError('unknown module selector')
    expected = {tag for tag in CATALOG if 'test' in modules or tag.split('_')[0] in modules}
    if tags:
        if not set(tags) <= expected:
            raise ValueError('unknown case or case outside selected module')
        expected = set(tags)
    return expected

try:
    mode = sys.argv[1]
    if mode == 'validate':
        selection(sys.argv[2:])
    else:
        log_path = Path(sys.argv[2])
        expected = selection(sys.argv[3:])
        raw = re.sub(r'\x1b\[[0-9;]*m', '', log_path.read_text())
        seen = {}
        current = None
        for line in raw.splitlines():
            match = re.search(r'(test\w+_\w+)\s+tag.id', line)
            if match:
                current = match.group(1)
                if current in seen:
                    raise ValueError('case executed twice: ' + current)
                seen[current] = 0
            match = re.search(r'http/runner.send\s+Passed (\d+)/(\d+)', line)
            if match and current and "[request]" in line:
                passed, total = map(int, match.groups())
                if passed != total:
                    raise ValueError('assertions failed for ' + current)
                seen[current] += passed
        if set(seen) != expected:
            raise ValueError('executed tags differ from requested tags: ' + str(seen))
        for tag, count in seen.items():
            if count < CATALOG[tag]:
                raise ValueError('missing relevant assertions for ' + tag)
        report = {'cases': [{'task': tag.split('_')[0], 'TagID': tag, 'passedAssertions': count} for tag, count in seen.items()], 'relevantAssertions': sum(seen.values())}
        log_path.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
except (ValueError, OSError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(2)
