#!/usr/bin/env python3
"""Package one frozen custody worker; never launch it or access Keychain items."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import development_signing

FIELDS = ('version', 'session', 'config', 'resources', 'consoleRequirement',
          'expectedUID', 'namespace', 'clientID', 'canonicalExecutable',
          'oldRequirement', 'newRequirement', 'alias', 'service', 'account',
          'journalRoot', 'expectedIdentity', 'preparation', 'installPlan', 'newCanonicalExecutable', 'approvalConsole', 'originalConsoleRequirement')
REQUIRED_FIELDS = FIELDS[:-6]


def encode_enrollment(value):
    # Public metadata only. Neither arbitrary config payloads nor embedded keys
    # are permitted in the signed launcher enrollment.
    if not isinstance(value, dict) or set(value) - set(FIELDS) or set(REQUIRED_FIELDS) - set(value):
        raise ValueError('Closed enrollment metadata required')
    if value['version'] not in (1,2,3) or (value['version']==2)!=('newCanonicalExecutable' in value) or type(value['expectedUID']) is not int or not 0 <= value['expectedUID'] <= 2**32-1:
        raise ValueError('Explicit enrollment version and UID required')
    if value['version']==2:
        target=value['newCanonicalExecutable']
        if not isinstance(target,str) or not target.startswith('/') or os.path.normpath(target)!=target or target==value['canonicalExecutable'] or not target.endswith('/Mechanize.app/Contents/Helpers/mechanize') or any(c in target for c in '\x00\r\n'):
            raise ValueError('Exact relocated broker path required')
    if value['version']==3:
        app=Path.home()/'Applications/Mechanize.app'
        config=Path(value['config']['path'])
        if Path(value['canonicalExecutable'])!=app/'Contents/Helpers/mechanize' or config.name!='config.json' or app==config.parent or app in config.parents or config.parent in app.parents:raise ValueError('Same-path app and external config required')
    approval=value.get('approvalConsole')
    if ('approvalConsole' in value)!=('originalConsoleRequirement' in value):raise ValueError('Separate original console requirement required')
    if 'approvalConsole' in value and approval is None:raise ValueError('Approval console cannot be null')
    if approval is not None:
        if value['version']!=2 or not isinstance(approval,dict) or set(approval)!={'installedPath','requirement','birth'} or approval['requirement']!=value['consoleRequirement'] or str(Path(approval['installedPath'])/'Contents/Helpers/mechanize')!=value['newCanonicalExecutable'] or not re.fullmatch(r'[1-9][0-9]*:(0|[1-9][0-9]{0,5})',approval['birth']):raise ValueError('Closed approval console required')
    for name in ('session', 'namespace'):
        if not isinstance(value[name], str) or not re.fullmatch('[0-9a-f]{64}', value[name]):
            raise ValueError('Bounded enrollment identifier required')
    for resource in [value['config']] + value['resources'] + ([value['installPlan']] if 'installPlan' in value else []):
        if not isinstance(resource, dict) or set(resource) != {'path', 'sha256'}:
            raise ValueError('Only private resource references and digests allowed')
        if not isinstance(resource['path'], str) or not Path(resource['path']).is_absolute() or not re.fullmatch('[0-9a-f]{64}', resource['sha256']):
            raise ValueError('Exact private resource path and digest required')
    ordered = {name: value[name] for name in FIELDS if name in value}
    if approval is not None:ordered['approvalConsole']={k:approval[k] for k in ('installedPath','requirement','birth')}
    ordered['config'] = {name: value['config'][name] for name in ('path', 'sha256')}
    ordered['resources'] = [{name: ref[name] for name in ('path', 'sha256')} for ref in value['resources']]
    if not ordered.get('expectedIdentity'):
        ordered.pop('expectedIdentity', None)
    if 'installPlan' in value:
        if value.get('expectedIdentity') or 'preparation' in value:
            raise ValueError('Installer, preparation and reconciliation modes are exclusive')
        ordered['installPlan'] = {key: value['installPlan'][key] for key in ('path', 'sha256')}
    if 'preparation' in value:
        plan = value['preparation']
        keys = ('mutationExecutable', 'mutationRequirement', 'mutationSHA256', 'runtimeManifestSHA256')
        if not isinstance(plan, dict) or set(plan) != set(keys) or value.get('expectedIdentity'):
            raise ValueError('Closed read-only preparation plan required')
        ordered['preparation'] = {key: plan[key] for key in keys}
    raw = json.dumps(ordered, ensure_ascii=False, separators=(',', ':')).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029').encode()
    if len(raw) > 49152:
        raise ValueError('Enrollment exceeds bound')
    return base64.b64encode(raw).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enrollment', required=True, type=Path, help='Private reviewed public-metadata enrollment JSON; never secret contents')
    parser.add_argument('--output-directory', required=True, type=Path, help='New private packaging directory')
    parser.add_argument('--signing-identity', help='Existing certificate SHA-1; defaults to ad-hoc')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('Packaging requires macOS')
    fd = os.open(args.enrollment, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 49152:
            parser.error('Enrollment must be an owned private bounded regular file')
        encoded = encode_enrollment(json.load(source))
    identity = development_signing.select_identity(args.signing_identity)
    args.output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    destination = args.output_directory.resolve()
    executable = destination / 'mechanize-custody-migration'
    root = Path(__file__).resolve().parents[1]
    subprocess.run(['go', 'build', '-ldflags', '-X main.embeddedEnrollment=' + encoded,
                    '-o', str(executable), './cmd/mechanize-custody-migration'], cwd=root, check=True)
    os.chmod(executable, 0o700)
    subprocess.run(['codesign', '--force', '--sign', identity, '--identifier', 'com.viant.mechanize.custody-migration', str(executable)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(executable)], check=True)
    development_signing.verify_certificate(executable, identity)
    result = subprocess.run(['codesign', '--display', '--verbose=4', str(executable)], check=True, capture_output=True, text=True)
    match = re.search(r'^CDHash=([0-9a-fA-F]{40})$', result.stderr, re.MULTILINE)
    if not match:
        raise ValueError('Signed worker CDHash unavailable')
    requirement = 'identifier "com.viant.mechanize.custody-migration" and cdhash H"' + match[1].lower() + '"'
    subprocess.run(['codesign', '--verify', '--strict', '--test-requirement', '=' + requirement, str(executable)], check=True)
    manifest = {'schemaVersion': 1, 'executable': str(executable), 'requirement': requirement,
                'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                'enrollmentSHA256': hashlib.sha256(base64.b64decode(encoded)).hexdigest(),
                'installationPerformed': False, 'migrationPerformed': False}
    with (destination / 'manifest.json').open('x') as output:
        json.dump(manifest, output, indent=2)
        output.write('\n')
    os.chmod(destination / 'manifest.json', 0o600)
    print(destination / 'manifest.json')


if __name__ == '__main__':
    main()
