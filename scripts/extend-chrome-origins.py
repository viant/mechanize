#!/usr/bin/env python3
"""Set website access on one existing development Chrome enrollment.

Preflight is read-only. Apply requires a stopped owned runtime, retains a private
backup, and changes only the selected grant's origins. It grants neither Chrome
website permission nor consent and does not enable credential delivery.
"""
import argparse
import copy
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('chrome_enrollment', ROOT / 'scripts/enroll-chrome.py')
enrollment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrollment)
lock_spec = importlib.util.spec_from_file_location('chrome_update_lock', ROOT / 'scripts/upgrade-console.py')
update_lock = importlib.util.module_from_spec(lock_spec)
lock_spec.loader.exec_module(update_lock)


def https_origin(value):
    if not isinstance(value, str) or len(value) > 512 or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError('exact HTTPS origin required')
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.username is not None or
            url.password is not None or url.path or url.query or url.fragment or
            url.netloc != url.netloc.lower() or '*' in value or
            re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?', url.netloc) is None):
        raise ValueError('exact canonical HTTPS origin required')
    if url.port is not None and (url.port == 443 or not 0 < url.port <= 65535):
        raise ValueError('canonical nondefault HTTPS port required')
    canonical = 'https://' + url.hostname + (':' + str(url.port) if url.port is not None else '')
    if value != canonical:
        raise ValueError('canonical exact origin required')
    return value


def prepare(config, principal, extension_id, origins=(), all_websites=False):
    if re.fullmatch('[a-p]{32}', extension_id or '') is None:
        raise ValueError('actual enrolled extension ID required')
    if not isinstance(all_websites, bool) or all_websites and origins:
        raise ValueError('one explicit website access mode required')
    additions = [https_origin(v) for v in origins]
    if not all_websites and (not additions or len(additions) > 20 or len(set(additions)) != len(additions)):
        raise ValueError('bounded unique origin list required')
    chrome = config.get('chrome')
    if not isinstance(chrome, dict) or chrome.get('fixtureEnrollment') is not False:
        raise ValueError('existing nonfixture Chrome enrollment required')
    expected = 'chrome-extension://' + extension_id + '/'
    matches = [(i, g) for i, g in enumerate(chrome.get('grants', []))
               if g.get('extensionOrigin') == expected and
               all(g.get('principal', {}).get(k, '') == principal.get(k, '')
                   for k in ('issuer', 'subject', 'tenant', 'namespace', 'clientId'))]
    if len(matches) != 1 or not principal.get('namespace') or not principal.get('clientId'):
        raise ValueError('one exactly owned enrolled channel required')
    users = [u for u in config.get('users', []) if u.get('subject') == principal.get('subject')
             and u.get('tenant', '') == principal.get('tenant', '')]
    if len(users) != 1 or not {'desktop:observe', 'desktop:control'}.issubset(principal.get('scopes', [])):
        raise ValueError('verified user and observe/control scopes required')
    if not users[0].get('desktopAccess') is True and any(v not in users[0].get('webOrigins', []) for v in additions):
        raise ValueError('origin outside existing user ceiling')
    index, grant = matches[0]
    existing = grant.get('origins')
    if grant.get('allWebsites') is not None and type(grant['allWebsites']) is not bool:
        raise ValueError('existing website scope must be a boolean')
    if all_websites:
        if users[0].get('desktopAccess') is not True:
            raise ValueError('all websites requires existing desktop-wide user ceiling')
        if not isinstance(existing, list) or grant.get('allWebsites') is True and existing:
            raise ValueError('existing website scope malformed')
        updated = copy.deepcopy(config)
        selected = updated['chrome']['grants'][index]
        selected['allWebsites'], selected['origins'] = True, []
        return updated, int(grant.get('allWebsites') is not True)
    if grant.get('allWebsites') is True:
        raise ValueError('selected additions cannot silently narrow all-websites access')
    if not isinstance(existing, list) or not existing or len(set(existing)) != len(existing):
        raise ValueError('existing origin enrollment malformed')
    merged = existing + [v for v in additions if v not in existing]
    if len(merged) > 20:
        raise ValueError('combined origin limit exceeded')
    updated = copy.deepcopy(config)
    updated['chrome']['grants'][index]['origins'] = merged
    return updated, len(merged) - len(existing)


def main():
    with contextlib.ExitStack() as cleanup:
        return perform(cleanup)


def perform(cleanup):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--extension-id', required=True)
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument('--origin', action='append')
    scope.add_argument('--all-websites', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--broker-stopped-verified', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS enrollment only')
    os.umask(0o077)
    root = enrollment.owned(args.installation, directory=True, private=True)
    if args.apply:
        cleanup.enter_context(update_lock.runtime_lock(root))
    path = root / 'config.json'
    original = enrollment.read(path)
    config = json.loads(original)
    manifest_path = enrollment.canonical(args.manifest)
    manifest = json.loads(enrollment.read(manifest_path))
    if manifest_path != Path(manifest['sourceRoot']) / 'dist/development/manifest.json':
        raise ValueError('frozen source build manifest required')
    enrollment.verify_installation(root, manifest, config)
    if args.all_websites and manifest.get('websiteAccessModes') != ['selected', 'all']:
        raise ValueError('installed frozen broker does not advertise all-websites enrollment')
    trust = config['chrome']['processTrust']
    enrollment.verify_image(Path(trust['chromeExecutable']), trust['chromeRequirement'])
    if trust['nativeHostExecutable'] != str(root / 'mechanize-native-host') or trust['nativeHostRequirement'] != manifest['nativeHostRequirement']:
        raise ValueError('native-host trust mismatch')
    with tempfile.TemporaryDirectory(prefix='mechanize-origin-preflight-') as temporary:
        work = Path(temporary).resolve()
        os.chmod(work, 0o700)
        source = work / 'main.go'
        source.write_text(enrollment.GO_HELPER)
        helper = work / 'verify'
        enrollment.run('go', 'build', '-o', str(helper), str(source), cwd=ROOT)
        selector = 'all-websites' if args.all_websites else https_origin(args.origin[0])
        principal = json.loads(enrollment.run(str(helper), 'verify', str(path), selector).stdout)
        updated, added = prepare(config, principal, args.extension_id, args.origin or (), args.all_websites)
        backup = None
        if args.apply and added:
            if not args.broker_stopped_verified:
                raise ValueError('verified stopped runtime boundary required')
            enrollment.require_stopped(root)
            enrollment.verify_installation(root, manifest, config)
            if enrollment.read(path) != original:
                raise ValueError('configuration changed after preflight')
            backup = Path(tempfile.mkdtemp(prefix='chrome-origin-backup-', dir=root))
            os.chmod(backup, 0o700)
            enrollment.atomic(backup / 'config.json', original, None)
            enrollment.require_stopped(root)
            enrollment.atomic(path, enrollment.encoded(updated), original)
        print(json.dumps({'applied': bool(args.apply and added), 'scopeChanged': bool(added),
                          'allWebsites': args.all_websites, 'addedOriginCount': 0 if args.all_websites else added,
                          'credentialsChanged': False, 'binariesChanged': False,
                          'chromePermissionGranted': False, 'credentialDeliveryQualified': False,
                          'backupRetained': backup is not None}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Chrome origin extension rejected; private details withheld', file=sys.stderr)
        sys.exit(1)
