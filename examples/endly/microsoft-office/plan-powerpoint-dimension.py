"""Emit the observed PowerPoint numeric-field route; Endly/MCP owns execution.

Use an owned disposable deck with one independently verified chart, already
selected on the current slide. UI receipts are observational; independently
inspect saved geometry. Never regenerate caseId to bypass a stopped run.
"""
import json
import re
import sys
from decimal import Decimal


def build(settings):
    required = {'processId', 'processStartToken', 'windowId', 'windowTitle',
                'caseId', 'control', 'value'}
    if not isinstance(settings, dict) or set(settings) != required:
        raise ValueError('Supply exactly the documented dimension parameters')
    for key, maximum in [('processId', 2147483647), ('windowId', 4294967295)]:
        if type(settings[key]) is not int or not 0 < settings[key] <= maximum:
            raise ValueError(f'{key} must be a positive bounded integer')
    for key in required - {'processId', 'windowId'}:
        value = settings[key]
        if not isinstance(value, str) or not value.strip() or len(value.encode()) > 255:
            raise ValueError(f'{key} must be a bounded nonempty string')
        if any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in '\u2028\u2029' for c in value):
            raise ValueError('Control-free single-line parameters required')
    if not re.fullmatch(r'[1-9][0-9]*:[0-9]+', settings['processStartToken']):
        raise ValueError('Fresh process birth token required')
    if settings['control'] not in ['Width:', 'Height:']:
        raise ValueError('Only the observed PowerPoint chart dimensions are qualified')
    if not re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,3})?', settings['value']) or not 0 < Decimal(settings['value']) <= 56:
        raise ValueError('Positive decimal dimension at most 56 required')

    string = lambda value: {'kind': 'string', 'string': value}
    surface = {'kind': 'native', 'bundleId': 'com.microsoft.Powerpoint',
               'processId': settings['processId'], 'processStartToken': settings['processStartToken']}
    window = settings['windowId']
    root = 'powerpoint.window(title: ' + json.dumps(settings['windowTitle']) + ')'
    field = 'powerpoint.focusedElement().getByRole("AXTextField", exact: true)'
    control = root + '.getByRole("AXIncrementor", name: ' + json.dumps(settings['control']) + ', exact: true)'

    def predicate(selector, attribute, expected, *, strategy='name', focused=False, literal=False):
        inputs = {'bundleID': string(surface['bundleId']),
                  'processId': {'kind': 'number', 'number': surface['processId']},
                  'processStartToken': string(surface['processStartToken']),
                  'strategy': string(strategy), 'selector': string(selector), 'attribute': string(attribute),
                  'expected': {'kind': 'boolean', 'boolean': expected} if isinstance(expected, bool) else string(expected)}
        inputs.update({'nativeRoot': string('focusedElement')} if focused else {'windowTitle': string(settings['windowTitle'])})
        return {'kind': 'adapter', 'adapter': 'native', 'name': 'literalValueMatches' if literal else 'valueEquals',
                'scope': {'surfaceRef': 'powerpoint'}, 'timeoutMs': 7000, 'freshnessMs': 1000,
                'requiredAuthority': 'observational', 'inputs': inputs}

    steps = []
    def add(name, command, post=None, pre=None):
        step = {'id': name, 'command': command, 'effect': {'businessKey': {'case': string(settings['caseId']), 'step': string(name)}}}
        if post is not None: step['postcondition'] = post
        if pre is not None: step['precondition'] = pre
        steps.append(step)

    # Caller must verify the single selected chart; this guard only rejects a
    # missing chart context and is not an exact chart identity proof.
    chart_context = predicate('Chart Design', 'enabled', True)
    focus = predicate(settings['control'], 'focused', True)
    literal = predicate('AXTextField', 'value', settings['value'], strategy='role', focused=True, literal=True)
    window_exists = predicate(settings['windowTitle'], 'name', settings['windowTitle'])
    add('activate', 'powerpoint.activate()')
    add('find', f'powerpoint.pressWindowKey(windowId: {window}, key: "Cmd+F")',
        predicate('AXTextField', 'role', 'AXTextField', strategy='role', focused=True), chart_context)
    add('stage', field + '.fill(' + json.dumps(settings['value']) + ')', literal)
    add('select-staging', field + '.pressKey("Cmd+A")', literal, literal)
    add('copy-staging', field + '.pressKey("Cmd+C")', literal, literal)
    add('return', field + '.pressKey("Escape")', window_exists)
    add('focus-control', control + '.focus()', focus, chart_context)
    add('select-value', control + '.pressKey("Cmd+A")', focus, focus)
    add('paste-value', control + '.pressKey("Cmd+V")', focus, focus)
    add('commit-value', control + '.pressKey("Return")', window_exists)
    return {'schemaVersion': 1, 'name': 'Set observed PowerPoint chart dimension',
            'surfaces': {'powerpoint': surface}, 'requires': {'adapters': ['native']}, 'steps': steps}


if __name__ == '__main__':
    try:
        json.dump(build(json.load(sys.stdin)), sys.stdout, ensure_ascii=False)
        sys.stdout.write('\n')
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
        raise SystemExit(str(error))
