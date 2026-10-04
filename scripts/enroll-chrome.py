#!/usr/bin/env python3
"""Preflight a pinned disposable Chrome enrollment; apply only when explicitly requested.
No restart, browser input, credential output, or default/MAC key selection.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
HOST_NAME = 'com.viant.mechanize'
CHROME_VENDOR_REQUIREMENT = ('identifier "com.google.Chrome" and anchor apple generic '
                             'and certificate leaf[subject.OU] = "EQHXZ8M8AV"')

# The local helper uses the application's real auth.Verifier and Scy. Verification
# loads existing plain local resources into Data with os.ReadFile so preflight
# cannot change their parent modes through AFS. No token/key is an argument.
GO_HELPER = r'''package main
import (
 "context"; "crypto/rand"; "encoding/hex"; "encoding/json"; "errors"; "io"; "os"; "path/filepath"; "strings"; "syscall"
 "github.com/viant/mechanize/auth"
 "github.com/viant/scy"
 "github.com/viant/scy/auth/jwt/verifier"
 "github.com/viant/scy/kms"
 _ "github.com/viant/scy/kms/blowfish"
)
type cfg struct { Keys verifier.Config `json:"keys"`; Policy auth.Policy `json:"identityPolicy"`; Credential *scy.Resource `json:"stdioCredential"`; Users []struct{Subject string `json:"subject"`;Tenant string `json:"tenant"`;Desktop bool `json:"desktopAccess"`;Origins []string `json:"webOrigins"`} `json:"users"` }
func private(path string)([]byte,error){
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return nil,errors.New("canonical private path required")}
 resolved,err:=filepath.EvalSymlinks(path);if err!=nil||resolved!=path{return nil,errors.New("symlink rejected")}
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW,0);if err!=nil{return nil,err};f:=os.NewFile(uintptr(fd),path);defer f.Close()
 info,err:=f.Stat();if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||info.Size()>1<<20{return nil,errors.New("private bounded file required")}
 owner,ok:=info.Sys().(*syscall.Stat_t);if !ok||owner.Uid!=uint32(os.Getuid())||owner.Nlink!=1{return nil,errors.New("private file ownership mismatch")}
 return io.ReadAll(io.LimitReader(f,1<<20+1))
}
func local(r *scy.Resource)(*scy.Resource,error){
 if r==nil||r.URL==""||r.Key!=""||r.Fallback!=nil||len(r.Data)!=0{return nil,errors.New("bounded verifier requires existing plain local file resource")}
 b,err:=private(r.URL);if err!=nil{return nil,err};copy:=*r;copy.Data=b;return &copy,nil
}
func verify(path string,origin string)error{
 raw,err:=private(path);if err!=nil{return err};var c cfg;if json.Unmarshal(raw,&c)!=nil{return errors.New("configuration unavailable")}
 if c.Keys.HMAC==nil||len(c.Keys.RSA)!=0||len(c.Keys.Rules)!=0||c.Keys.CertURL!=""||len(c.Policy.Algorithms)!=1||c.Policy.Algorithms[0]!="HS256"{return errors.New("local development HS256 verifier required")}
 c.Keys.HMAC,err=local(c.Keys.HMAC);if err!=nil{return err};credential,err:=local(c.Credential);if err!=nil{return err}
 token,err:=scy.New().Load(context.Background(),credential);if err!=nil{return err}
 v,err:=auth.NewVerifier(context.Background(),&c.Keys,c.Policy);if err!=nil{return err};p,err:=v.Verify(context.Background(),strings.TrimSpace(token.String()));if err!=nil{return err}
 if !p.HasScope("desktop:observe")||!p.HasScope("desktop:control"){return errors.New("verified observe/control principal required")}
 owned:=false;for _,u:=range c.Users{if u.Subject!=p.Subject||u.Tenant!=p.Tenant{continue};owned=u.Desktop;for _,o:=range u.Origins{owned=owned||o==origin}}
 if !owned{return errors.New("principal origin is outside user ceiling")}
 return json.NewEncoder(os.Stdout).Encode(p)
}
func write(path string,data []byte)error{f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if err!=nil{return err};defer f.Close();if _,err=f.Write(data);err!=nil{return err};return f.Sync()}
func provision(keyPath,credentialPath string)error{
 keyRef:="blowfish://file"+keyPath;k,err:=kms.NewKey(keyRef);if err!=nil||k.Scheme!="blowfish"||k.Kind!="file"||k.Path!=keyPath{return errors.New("Scy file key parser mismatch")}
 key:=make([]byte,32);credential:=make([]byte,32);if _,err=rand.Read(key);err!=nil{return err};if _,err=rand.Read(credential);err!=nil{return err}
 if err=write(keyPath,key);err!=nil{return err};resource:=scy.Resource{URL:credentialPath,Key:keyRef};secret:=hex.EncodeToString(credential)
 if err=scy.New().Store(context.Background(),scy.NewSecret(secret,&resource));err!=nil{return err}
 if err=os.Chmod(credentialPath,0600);err!=nil{return err};f,err:=os.OpenFile(credentialPath,os.O_RDWR|syscall.O_NOFOLLOW,0600);if err!=nil{return err};if err=f.Sync();err!=nil{f.Close();return err};if err=f.Close();err!=nil{return err};loaded,err:=scy.New().Load(context.Background(),&resource);if err!=nil||loaded.String()!=secret{return errors.New("Scy encrypted resource roundtrip mismatch")}
 if err=os.Chmod(keyPath,0600);err!=nil{return err};for _,p:=range []string{filepath.Dir(keyPath),filepath.Dir(credentialPath)}{if err=os.Chmod(p,0700);err!=nil{return err}}
 for i:=range key{key[i]=0};for i:=range credential{credential[i]=0};return nil
}
func main(){
 var err error
 if len(os.Args)==4&&os.Args[1]=="verify"{err=verify(os.Args[2],os.Args[3])}else if len(os.Args)==4&&os.Args[1]=="provision"{err=provision(os.Args[2],os.Args[3])}else{err=errors.New("bounded enrollment helper arguments required")}
 if err!=nil{os.Stderr.WriteString("Chrome enrollment helper failed; secret details withheld\n");os.Exit(1)}
}'''


def canonical(path, existing=True):
    p = Path(path)
    if not p.is_absolute() or os.path.normpath(str(p)) != str(p):
        raise ValueError('canonical absolute path required')
    for part in [*reversed(p.parents), p]:
        if part.is_symlink():
            raise ValueError('symlink path rejected')
    if existing and not p.exists():
        raise ValueError('required enrollment path is absent')
    return p


def owned(path, directory=False, private=False, executable=False):
    p = canonical(path)
    s = p.stat()
    kind = stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)
    if not kind or s.st_uid not in ((os.getuid(),) if private else (os.getuid(), 0)) or s.st_mode & (0o077 if private else 0o022):
        raise ValueError('enrollment path ownership/mode mismatch')
    if not directory and (s.st_nlink != 1 or (executable and not s.st_mode & 0o111)):
        raise ValueError('regular unlinked executable/file required')
    return p


def read(path, private=True):
    p = owned(path, private=private)
    if p.stat().st_size > 1 << 20:
        raise ValueError('bounded enrollment metadata required')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        return f.read()


def native_manifest_path(user_data):
    # Chromium DIR_USER_NATIVE_MESSAGING derives from DIR_USER_DATA, including
    # --user-data-dir. Do not register a disposable host in the default profile.
    root = owned(user_data, directory=True, private=True)
    return canonical(root / 'NativeMessagingHosts' / (HOST_NAME + '.json'), existing=False)


def run(*args, cwd=None):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    if result.returncode:
        raise RuntimeError(Path(args[0]).name + ' failed; output withheld')
    return result


def encoded(value):
    return json.dumps(value, indent=2).encode() + b'\n'


def verify_image(path, requirement, digest=None):
    path = owned(path, executable=True)
    image_pin = r'(?:identifier "[A-Za-z0-9._-]+" and )?cdhash H"[a-f0-9]{40}"'
    chrome_pin = (re.escape(CHROME_VENDOR_REQUIREMENT) +
                  r' and (?:cdhash H"[a-f0-9]{40}"|\(cdhash H"[a-f0-9]{40}" or cdhash H"[a-f0-9]{40}"\))')
    if not isinstance(requirement, str) or not re.fullmatch('(?:' + image_pin + '|' + chrome_pin + ')', requirement):
        raise ValueError('exact signed image requirement required')
    if requirement.startswith(CHROME_VENDOR_REQUIREMENT):
        hashes = re.findall(r'cdhash H"([a-f0-9]{40})"', requirement)
        if hashes != sorted(set(hashes)):
            raise ValueError('unique canonical Chrome image hashes required')
    if digest and (not re.fullmatch('[a-f0-9]{64}', digest) or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise ValueError('manifest image digest mismatch')
    run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '--test-requirement', '=' + requirement, str(path))


def current_chrome_requirement(path):
    path = owned(path, executable=True)
    # An ad-hoc lookalike can claim the identifier and a valid self-hash. Require
    # Apple's certificate chain and Google's publisher before freezing that hash.
    run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '--test-requirement',
        '=' + CHROME_VENDOR_REQUIREMENT, str(path))
    # Use only the fixed local tool, never PATH or caller-supplied architecture
    # claims. Chrome supports a thin slice or the exact Intel/Apple Silicon pair.
    discovery = run('/usr/bin/lipo', '-archs', str(path))
    if (len(discovery.stdout) > 128 or discovery.stderr or
            not re.fullmatch(rb'(?:x86_64|arm64)(?: (?:x86_64|arm64))?\n?', discovery.stdout)):
        raise ValueError('bounded supported Chrome architectures required')
    architectures = discovery.stdout.decode('ascii').strip().split(' ')
    if len(architectures) != len(set(architectures)):
        raise ValueError('unique supported Chrome architectures required')
    hashes = []
    for architecture in sorted(architectures):
        run('/usr/bin/codesign', '--verify', '--strict', '--architecture', architecture,
            '--test-requirement', '=' + CHROME_VENDOR_REQUIREMENT, str(path))
        result = run('/usr/bin/codesign', '--display', '--verbose=4', '--architecture', architecture, str(path))
        if result.stdout or len(result.stderr) > 16384:
            raise ValueError('bounded signed Chrome slice metadata required')
        metadata = result.stderr.splitlines()
        hash_lines = [line for line in metadata if line.startswith(b'CDHash=')]
        identifiers = [line for line in metadata if line.startswith(b'Identifier=')]
        if (len(hash_lines) != 1 or not re.fullmatch(rb'CDHash=[a-fA-F0-9]{40}', hash_lines[0]) or
                identifiers != [b'Identifier=com.google.Chrome']):
            raise ValueError('signed Google Chrome slice identity unavailable')
        hashes.append(hash_lines[0][7:].decode('ascii').lower())
    if len(hashes) != len(set(hashes)):
        raise ValueError('unique Chrome slice hashes required')
    pins = ['cdhash H"' + value + '"' for value in sorted(hashes)]
    clause = pins[0] if len(pins) == 1 else '(' + ' or '.join(pins) + ')'
    requirement = CHROME_VENDOR_REQUIREMENT + ' and ' + clause
    verify_image(path, requirement)
    return requirement


def verify_installation(installation, manifest, config):
    source = canonical(manifest['sourceRoot'])
    if manifest.get('schemaVersion') != 1 or manifest.get('mode') != 'development' or manifest.get('productionQualified') is not False or config.get('sourceRoot') != str(source):
        raise ValueError('chosen manifest must match installed development source')
    for name, filename in [('broker', 'mechanize'), ('nativeHost', 'mechanize-native-host')]:
        if manifest.get(name) != str(source / 'dist/development' / filename):
            raise ValueError('manifest artifact source mismatch')
        digest = manifest.get(name + 'SHA256')
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('manifest SHA256 is mandatory')
        verify_image(installation / filename, manifest[name + 'Requirement'], digest)
    expected = manifest['brokerRequirement'].encode()
    pins = set(re.findall(rb'identifier "com\.viant\.mechanize\.broker" and cdhash H"[a-f0-9]{40}"', (installation / 'mechanize-native-host').read_bytes()))
    if pins != {expected} or manifest.get('nativeHostBrokerRequirement') != manifest['brokerRequirement']:
        raise ValueError('native host embedded broker reverse pin mismatch')


def require_stopped(installation):
    executables = {str(installation / name) for name in ['mechanize', 'mechanize-native', 'mechanize-native-host']}
    for line in run('/bin/ps', '-ww', '-axo', 'uid=,pid=,comm=').stdout.decode().splitlines():
        row = line.strip().split(None, 2)
        if len(row) == 3 and row[0] == str(os.getuid()) and row[2] in executables:
            raise ValueError('enrolled broker/helper/native host must be stopped before configuration replacement')


def mkdir_private(path):
    p = canonical(path, existing=False)
    p.mkdir(mode=0o700)
    return p


def atomic(path, payload, expected):
    path = canonical(path, existing=False)
    current = read(path, private=False) if path.exists() else None
    if current != expected:
        raise ValueError('enrollment target changed after preflight; retained backup requires review')
    fd, temporary = tempfile.mkstemp(prefix='.chrome-enroll-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def make_configs(config, plan, principal, trust, extension_id, socket, resource, broker_requirement):
    result = copy.deepcopy(config)
    old_chrome = result.get('chrome')
    if old_chrome is not None:
        raise ValueError('existing Chrome enrollment is preserved; explicit migration/review required')
    origin = 'chrome-extension://' + extension_id + '/'
    grant = dict(principal=principal, profileChannel=plan['profileChannel'], browserInstance=plan['browserInstance'], extensionOrigin=origin,
                 origins=plan['origins'], credentialResource=resource, profileDirectory=plan['profileDirectory'])
    result['chrome'] = dict(socketPath=socket, fixtureEnrollment=False, processTrust=trust, grants=[grant])
    host = dict(socketPath=socket, fixtureEnrollment=False, processTrust=trust, profileChannel=plan['profileChannel'], browserInstance=plan['browserInstance'],
                extensionOrigin=origin, credentialResource=resource, brokerRequirement=broker_requirement, profileDirectory=plan['profileDirectory'])
    native_manifest = dict(name=HOST_NAME, description='Mechanize disposable-profile development enrollment', path=trust['nativeHostExecutable'], type='stdio',
                           supports_native_initiated_connections=True, allowed_origins=[origin])
    scope = plan.get('trustScope', 'profile')
    if scope not in ('profile', 'desktop'):
        raise ValueError('closed explicit browser trust scope required')
    if scope == 'desktop':
        users = [u for u in config.get('users', []) if u.get('subject') == principal.get('subject') and
                 u.get('tenant', '') == principal.get('tenant', '')]
        if (not principal.get('subject') or len(users) != 1 or users[0].get('desktopAccess') is not True or
                principal.get('issuer') != config.get('identityPolicy', {}).get('issuer')):
            raise ValueError('desktop browser enrollment requires the existing desktop-wide user')
        grant['trustScope'] = host['trustScope'] = 'desktop'
        grant['profileDirectory'] = host['profileDirectory'] = ''
    return result, host, native_manifest


def self_test():
    # Synthetic fixtures only: no live inputs, enrollment credentials or image pins.
    import base64
    import hmac
    import unittest
    from unittest import mock

    class EnrollmentTests(unittest.TestCase):
        def test_native_manifest_uses_exact_private_user_data_directory(self):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                root.chmod(0o700)
                expected = root / 'NativeMessagingHosts' / (HOST_NAME + '.json')
                self.assertEqual(native_manifest_path(root), expected)
                self.assertFalse(expected.parent.exists())
                root.chmod(0o755)
                with self.assertRaises(ValueError):
                    native_manifest_path(root)
                root.chmod(0o700)
                other = root / 'other'
                other.mkdir(mode=0o700)
                expected.parent.symlink_to(other, target_is_directory=True)
                with self.assertRaises(ValueError):
                    native_manifest_path(root)

        def test_chrome_publisher_is_required_before_hash_pin(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'chrome'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                calls = []

                def signed(*args, **kwargs):
                    calls.append(args)
                    if args[0] == '/usr/bin/lipo':
                        return subprocess.CompletedProcess(args, 0, b'arm64\n', b'')
                    metadata = b'Identifier=com.google.Chrome\nCDHash=' + b'a' * 40 + b'\n'
                    return subprocess.CompletedProcess(args, 0, b'', metadata if '--display' in args else b'')

                with mock.patch.dict(globals(), {'run': signed}):
                    requirement = current_chrome_requirement(image)
                self.assertIn('=' + CHROME_VENDOR_REQUIREMENT, calls[0])
                self.assertEqual(requirement, CHROME_VENDOR_REQUIREMENT + ' and cdhash H"' + 'a' * 40 + '"')
                self.assertIn('=' + requirement, calls[-1])
                self.assertIn('--all-architectures', calls[-1])
                display = [call for call in calls if '--display' in call]
                self.assertEqual(len(display), 1)
                self.assertIn('arm64', display[0])
                rejected = mock.Mock(side_effect=RuntimeError('publisher rejected'))
                with mock.patch.dict(globals(), {'run': rejected}):
                    with self.assertRaises(RuntimeError):
                        current_chrome_requirement(image)
                self.assertEqual(rejected.call_count, 1)
                image.chmod(0o775)
                untouched = mock.Mock()
                with mock.patch.dict(globals(), {'run': untouched}):
                    with self.assertRaises(ValueError):
                        current_chrome_requirement(image)
                untouched.assert_not_called()

        def test_universal_chrome_pins_every_publisher_validated_slice(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'chrome'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                calls = []

                def signed(*args, **kwargs):
                    calls.append(args)
                    if args[0] == '/usr/bin/lipo':
                        return subprocess.CompletedProcess(args, 0, b'x86_64 arm64\n', b'')
                    metadata = b''
                    if '--display' in args:
                        architecture = args[args.index('--architecture') + 1]
                        value = b'A' * 40 if architecture == 'arm64' else b'b' * 40
                        metadata = b'Identifier=com.google.Chrome\nCDHash=' + value + b'\n'
                    return subprocess.CompletedProcess(args, 0, b'', metadata)

                with mock.patch.dict(globals(), {'run': signed}):
                    requirement = current_chrome_requirement(image)
                expected = CHROME_VENDOR_REQUIREMENT + ' and (cdhash H"' + 'a' * 40 + '" or cdhash H"' + 'b' * 40 + '")'
                self.assertEqual(requirement, expected)
                verified_slices = [call[call.index('--architecture') + 1] for call in calls
                                   if '--verify' in call and '--architecture' in call]
                self.assertEqual(verified_slices, ['arm64', 'x86_64'])
                self.assertIn('=' + expected, calls[-1])
                self.assertIn('--all-architectures', calls[-1])
                reversed_arches = lambda *args, **kwargs: (subprocess.CompletedProcess(args, 0, b'arm64 x86_64\n', b'')
                                                          if args[0] == '/usr/bin/lipo' else signed(*args, **kwargs))
                with mock.patch.dict(globals(), {'run': reversed_arches}):
                    self.assertEqual(current_chrome_requirement(image), expected)

        def test_chrome_rejects_unknown_duplicate_or_malformed_architectures(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'chrome'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                for output in [b'', b'i386\n', b'arm64e\n', b'arm64 arm64\n', b'x86_64 arm64 arm64\n',
                               b'x86_64\narm64\n', b'x86_64 arm64\njunk', b' arm64\n', b'arm64\xff', b'arm64 ']:
                    with self.subTest(output=output):
                        calls = []

                        def discovery(*args, **kwargs):
                            calls.append(args)
                            return subprocess.CompletedProcess(args, 0, output if args[0] == '/usr/bin/lipo' else b'', b'')

                        with mock.patch.dict(globals(), {'run': discovery}):
                            with self.assertRaises(ValueError):
                                current_chrome_requirement(image)
                        self.assertFalse(any('--display' in call for call in calls))

        def test_chrome_rejects_malformed_or_duplicate_slice_metadata(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'chrome'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                valid = b'Identifier=com.google.Chrome\nCDHash=' + b'a' * 40 + b'\n'
                for metadata in [b'', valid + b'CDHash=' + b'b' * 40 + b'\n', valid + b'Identifier=com.google.Chrome\n',
                                 b'Identifier=evil\nCDHash=' + b'a' * 40 + b'\n',
                                 b'Identifier=com.google.Chrome\nCDHash=' + b'a' * 39 + b'\n', valid + b'x' * 16385]:
                    with self.subTest(metadata_length=len(metadata)):

                        def signed(*args, **kwargs):
                            return subprocess.CompletedProcess(args, 0, b'arm64\n' if args[0] == '/usr/bin/lipo' else b'',
                                                               metadata if '--display' in args else b'')

                        with mock.patch.dict(globals(), {'run': signed}):
                            with self.assertRaises(ValueError):
                                current_chrome_requirement(image)

                def duplicate_hash(*args, **kwargs):
                    return subprocess.CompletedProcess(args, 0, b'arm64 x86_64\n' if args[0] == '/usr/bin/lipo' else b'',
                                                       valid if '--display' in args else b'')

                with mock.patch.dict(globals(), {'run': duplicate_hash}):
                    with self.assertRaises(ValueError):
                        current_chrome_requirement(image)

        def test_chrome_second_slice_publisher_rejection_stops_pin_creation(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'chrome'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                calls = []

                def rejected(*args, **kwargs):
                    calls.append(args)
                    if args[0] == '/usr/bin/lipo':
                        return subprocess.CompletedProcess(args, 0, b'arm64 x86_64\n', b'')
                    if '--verify' in args and '--architecture' in args and 'x86_64' in args:
                        raise RuntimeError('publisher rejected')
                    return subprocess.CompletedProcess(args, 0, b'',
                                                       b'Identifier=com.google.Chrome\nCDHash=' + b'a' * 40 + b'\n' if '--display' in args else b'')

                with mock.patch.dict(globals(), {'run': rejected}):
                    with self.assertRaises(RuntimeError):
                        current_chrome_requirement(image)
                self.assertFalse(any('--display' in call and 'x86_64' in call for call in calls))
                self.assertEqual(sum('--all-architectures' in call for call in calls), 1)

        def test_image_requirement_whitelist_keeps_exact_hash_and_digest_bounds(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'image'
                image.write_bytes(b'fixture')
                image.chmod(0o755)
                first, second = 'cdhash H"' + 'a' * 40 + '"', 'cdhash H"' + 'b' * 40 + '"'
                valid = [first, 'identifier "fixture.helper" and ' + first,
                         CHROME_VENDOR_REQUIREMENT + ' and ' + first,
                         CHROME_VENDOR_REQUIREMENT + ' and (' + first + ' or ' + second + ')']
                runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b'', b''))
                with mock.patch.dict(globals(), {'run': runner}):
                    for requirement in valid:
                        verify_image(image, requirement, hashlib.sha256(b'fixture').hexdigest())
                self.assertEqual(runner.call_count, len(valid))
                runner.reset_mock()
                invalid = [CHROME_VENDOR_REQUIREMENT, CHROME_VENDOR_REQUIREMENT + ' or ' + first,
                           '(' + first + ' or ' + second + ')',
                           CHROME_VENDOR_REQUIREMENT + ' and (' + first + ' or ' + first + ')',
                           CHROME_VENDOR_REQUIREMENT + ' and (' + second + ' or ' + first + ')',
                           CHROME_VENDOR_REQUIREMENT + ' and (' + first + ' or ' + second + ' or ' + first + ')',
                           CHROME_VENDOR_REQUIREMENT + ' and (' + first + ' or true)',
                           'identifier "fixture.helper" and (' + first + ' or ' + second + ')']
                with mock.patch.dict(globals(), {'run': runner}):
                    for requirement in invalid:
                        with self.subTest(requirement=requirement):
                            with self.assertRaises(ValueError):
                                verify_image(image, requirement)
                    with self.assertRaises(ValueError):
                        verify_image(image, valid[-1], '0' * 64)
                runner.assert_not_called()

        def test_ad_hoc_chrome_identifier_is_not_google_provenance(self):
            with tempfile.TemporaryDirectory() as tmp:
                image = Path(tmp).resolve() / 'lookalike'
                image.write_bytes(Path('/usr/bin/true').read_bytes())
                image.chmod(0o755)
                run('/usr/bin/codesign', '--force', '--sign', '-', '--identifier', 'com.google.Chrome', str(image))
                run('/usr/bin/codesign', '--verify', '--strict', str(image))
                with self.assertRaises(RuntimeError):
                    current_chrome_requirement(image)

        def test_config_shapes_preserve_original(self):
            original = {'unrelated': {'keep': True}}
            plan = {'profileChannel': 'fixture-channel', 'browserInstance': 'fixture-browser',
                    'profileDirectory': '/private/fixture/Default', 'origins': ['http://127.0.0.1:18771']}
            principal = {'namespace': 'fixture-namespace'}
            trust = {'nativeHostExecutable': '/private/fixture/native-host'}
            resource = {'URL': '/private/fixture/secrets/ciphertext/enrollment.sec',
                        'Key': 'blowfish://file/private/fixture/secrets/key/enrollment.key'}
            cfg, host, manifest = make_configs(original, plan, principal, trust, 'a' * 32,
                                               '/private/fixture/transport/broker.sock', resource, 'fixture-pin')
            self.assertEqual(original, {'unrelated': {'keep': True}})
            self.assertEqual(cfg['chrome']['grants'][0]['credentialResource'], host['credentialResource'])
            self.assertEqual(manifest['allowed_origins'], ['chrome-extension://' + 'a' * 32 + '/'])
            self.assertTrue(manifest['supports_native_initiated_connections'])
            self.assertFalse(host['fixtureEnrollment'])
            with self.assertRaises(ValueError):
                make_configs(cfg, plan, principal, trust, 'a' * 32, '/private/fixture/socket', resource, 'fixture-pin')

        def test_desktop_scope_is_explicit_and_requires_blanket_user(self):
            original = {'identityPolicy': {'issuer': 'fixture'}, 'users': [{'subject': 'owner', 'desktopAccess': True}]}
            plan = {'profileChannel': 'channel', 'browserInstance': 'browser', 'profileDirectory': '/private/fixture/Default',
                    'origins': ['http://127.0.0.1:18771'], 'trustScope': 'desktop'}
            principal = {'issuer': 'fixture', 'subject': 'owner', 'namespace': 'fixture-namespace'}
            resource = {'URL': '/private/fixture/enrollment.sec', 'Key': 'blowfish://file/private/fixture/key'}
            def prepare():
                return make_configs(original, plan, principal, {'nativeHostExecutable': '/private/fixture/native-host'},
                                    'a' * 32, '/private/fixture/socket', resource, 'fixture-pin')
            config, host, _ = prepare()
            self.assertEqual(config['chrome']['grants'][0]['trustScope'], 'desktop')
            self.assertEqual(host['trustScope'], 'desktop')
            self.assertEqual(config['chrome']['grants'][0]['profileDirectory'], '')
            self.assertEqual(host['profileDirectory'], '')
            self.assertEqual(host['credentialResource'], resource)
            original['users'][0]['desktopAccess'] = False
            with self.assertRaises(ValueError):
                prepare()
            plan.pop('trustScope')
            config, host, _ = prepare()
            self.assertNotIn('trustScope', host)
            self.assertEqual(host['profileDirectory'], plan['profileDirectory'])

        def test_private_paths_and_atomic_cas(self):
            short_socket = Path('/private/tmp') / ('mce-' + str(os.getuid()) + '-' + 'a' * 12) / 'transport/broker.sock'
            self.assertLessEqual(len(str(short_socket).encode()), 103)
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                target = root / 'config.json'
                target.write_bytes(b'original')
                target.chmod(0o600)
                atomic(target, b'replacement', b'original')
                self.assertEqual(read(target), b'replacement')
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                with self.assertRaises(ValueError):
                    atomic(target, b'overwrite', b'original')
                link = root / 'linked'
                link.symlink_to(target)
                with self.assertRaises(ValueError):
                    read(link)

        def test_actual_scy_auth_verifier_with_synthetic_token(self):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                root.chmod(0o700)
                source = root / 'main.go'
                source.write_text(GO_HELPER)
                helper = root / 'verifier'
                run('go', 'build', '-o', str(helper), str(source), cwd=ROOT)
                key = b'fixture-only-hmac-key-32-bytes-xx'
                key_path, token_path, cfg_path = root / 'hmac', root / 'stdio.jwt', root / 'config.json'
                key_path.write_bytes(base64.b64encode(key))
                policy = dict(issuer='fixture-enrollment', audience='fixture-enrollment', algorithms=['HS256'],
                              clients={'fixture-client': 'Fixture client'})
                cfg = dict(keys={'HMAC': {'URL': str(key_path)}}, identityPolicy=policy,
                           stdioCredential={'URL': str(token_path)}, users=[dict(subject='fixture-owner', desktopAccess=True)])
                cfg_path.write_bytes(encoded(cfg))
                for p in [key_path, cfg_path]:
                    p.chmod(0o600)

                def token(expiration):
                    encode = lambda v: base64.urlsafe_b64encode(json.dumps(v, separators=(',', ':')).encode()).rstrip(b'=')
                    first = encode(dict(alg='HS256', typ='JWT'))
                    second = encode(dict(iss=policy['issuer'], aud=policy['audience'], sub='fixture-owner',
                                         client_id='fixture-client', scope='desktop:observe desktop:control', exp=expiration))
                    value = first + b'.' + second
                    return value + b'.' + base64.urlsafe_b64encode(hmac.new(key, value, hashlib.sha256).digest()).rstrip(b'=')

                token_path.write_bytes(token(int(time.time()) + 120))
                token_path.chmod(0o600)
                before = {str(p): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in [key_path, token_path, cfg_path]}
                verified = json.loads(run(str(helper), 'verify', str(cfg_path), 'http://127.0.0.1:18771').stdout)
                self.assertEqual(verified['subject'], 'fixture-owner')
                self.assertIn('desktop:control', verified['scopes'])
                for p in [key_path, token_path, cfg_path]:
                    self.assertEqual((p.read_bytes(), stat.S_IMODE(p.stat().st_mode)), before[str(p)])
                token_path.write_bytes(token(int(time.time()) - 10))
                with self.assertRaises(RuntimeError):
                    run(str(helper), 'verify', str(cfg_path), 'http://127.0.0.1:18771')
                token_path.write_bytes(b'invalid-token')
                with self.assertRaises(RuntimeError):
                    run(str(helper), 'verify', str(cfg_path), 'http://127.0.0.1:18771')

    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(EnrollmentTests))
    if not result.wasSuccessful():
        raise RuntimeError('enrollment fixture tests failed')


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--qualification-plan', required=True)
    parser.add_argument('--extension-id', required=True, help='actual 32-character Chrome-reported ID; never derived or guessed')
    parser.add_argument('--trust-scope', choices=['profile', 'desktop'], default='profile', help='explicit desktop scope requires a desktop-wide user; profile mode never falls back')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--apply', action='store_true')
    parser.add_argument('--broker-stopped-verified', action='store_true', help='operator has independently inhibited/stopped owned execution; apply also checks exact executables')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS enrollment only')
    if not re.fullmatch('[a-p]{32}', args.extension_id):
        raise ValueError('actual Chrome-reported extension ID required')
    os.umask(0o077)
    installation = owned(args.installation, directory=True, private=True)
    config_path = installation / 'config.json'
    original = read(config_path)
    config = json.loads(original)
    manifest_path = canonical(args.manifest)
    manifest = json.loads(read(manifest_path))
    if manifest_path != Path(manifest['sourceRoot']) / 'dist/development/manifest.json':
        raise ValueError('chosen manifest must be the frozen source build manifest')
    verify_installation(installation, manifest, config)
    plan = json.loads(read(args.qualification_plan))
    if 'trustScope' in plan and plan['trustScope'] != args.trust_scope:
        raise ValueError('operator trust-scope switch disagrees with qualification plan')
    plan['trustScope'] = args.trust_scope
    if plan.get('productionQualified') is not False:
        raise ValueError('explicit disposable development plan required')
    user_data = owned(plan['userDataDir'], directory=True, private=True)
    profile = owned(plan['profileDirectory'], directory=True)
    if profile != user_data / 'Default' or len(str(profile)) > 512:
        raise ValueError('exact canonical disposable Default profile required')
    for name in ['profileChannel', 'browserInstance']:
        if not re.fullmatch('[A-Za-z0-9._-]{1,128}', plan[name]):
            raise ValueError('bounded channel/browser identity required')
    if plan['origins'] != ['http://127.0.0.1:18771']:
        raise ValueError('this bounded enrollment supports only the planned loopback qualification origin')
    chrome_requirement = current_chrome_requirement(plan['chromeExecutable'])
    support = owned(Path.home() / 'Library/Application Support/Mechanize', directory=True, private=True)
    host_path = support / 'native-host.json'
    manifest_install = native_manifest_path(user_data)
    snapshots = [(config_path, original)]
    for path in [host_path, manifest_install]:
        snapshots.append((path, read(path, private=(path == host_path)) if path.exists() else None))
    with tempfile.TemporaryDirectory(prefix='mechanize-enrollment-preflight-') as temporary:
        work = Path(temporary).resolve()
        os.chmod(work, 0o700)
        helper_source = work / 'main.go'
        helper_source.write_text(GO_HELPER)
        helper = work / 'enroller'
        run('go', 'build', '-o', str(helper), str(helper_source), cwd=ROOT)
        principal = json.loads(run(str(helper), 'verify', str(config_path), plan['origins'][0]).stdout)
        trust = dict(expectedUID=os.getuid(), nativeHostExecutable=str(installation / 'mechanize-native-host'), nativeHostRequirement=manifest['nativeHostRequirement'],
                     chromeExecutable=plan['chromeExecutable'], chromeRequirement=chrome_requirement, maximumAncestors=1)
        placeholder = support / 'chrome-enrollments' / 'NEW-PRIVATE-ENROLLMENT'
        resource = {'URL': str(placeholder / 'secrets/ciphertext/enrollment.sec'), 'Key': 'blowfish://file' + str(placeholder / 'secrets/key/enrollment.key')}
        prepared = make_configs(config, plan, principal, trust, args.extension_id, str(Path('/private/tmp') / ('mce-' + str(os.getuid()) + '-NEW-ENROLLMENT') / 'transport/broker.sock'), resource, manifest['brokerRequirement'])
        if not args.apply:
            print(json.dumps(dict(dryRun=True, configWrites=False, credentialsGenerated=False, productionQualified=False,
                                 namespace=principal['namespace'], extensionOrigin=prepared[1]['extensionOrigin'], profileDirectory=str(profile),
                                 targets=[str(p) for p, _ in snapshots], nextStep='review, stop owned runtime, then explicitly apply')))
            return
        if not args.broker_stopped_verified:
            raise ValueError('apply requires independent stopped-runtime verification')
        require_stopped(installation)
        base = support / 'chrome-enrollments'
        if base.exists():
            owned(base, directory=True, private=True)
        else:
            mkdir_private(base)
        enrollment = mkdir_private(base / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:12]))
        backup = mkdir_private(enrollment / 'backup')
        socket_root = mkdir_private(Path('/private/tmp') / ('mce-' + str(os.getuid()) + '-' + uuid.uuid4().hex[:12]))
        transport = mkdir_private(socket_root / 'transport')
        if len(str(transport / 'broker.sock').encode()) > 103:
            raise ValueError('Darwin Unix socket path exceeds its byte bound')
        secrets = mkdir_private(enrollment / 'secrets')
        key_leaf = mkdir_private(secrets / 'key')
        ciphertext_leaf = mkdir_private(secrets / 'ciphertext')
        for index, (path, before) in enumerate(snapshots):
            if before is not None:
                (backup / (str(index) + '.json')).write_bytes(before)
        (backup / 'targets.json').write_bytes(encoded([dict(path=str(p), present=b is not None, sha256=hashlib.sha256(b).hexdigest() if b is not None else None) for p, b in snapshots]))
        for leaf in backup.iterdir():
            leaf.chmod(0o600)
        print(json.dumps(dict(phase='backed-up', backup=str(backup), enrollmentRoot=str(enrollment), socketRoot=str(socket_root))), flush=True)
        key_path, credential_path = key_leaf / 'enrollment.key', ciphertext_leaf / 'enrollment.sec'
        run(str(helper), 'provision', str(key_path), str(credential_path))
        owned(enrollment, directory=True, private=True); owned(secrets, directory=True, private=True); owned(transport, directory=True, private=True)
        resource = {'URL': str(credential_path), 'Key': 'blowfish://file' + str(key_path)}
        prepared = make_configs(config, plan, principal, trust, args.extension_id, str(transport / 'broker.sock'), resource, manifest['brokerRequirement'])
        verify_installation(installation, manifest, config)
        require_stopped(installation)
        for path, before in snapshots:
            if (read(path, private=False) if path.exists() else None) != before:
                raise ValueError('enrollment configuration changed; backup retained, no replacement attempted')
        parent = manifest_install.parent
        if not parent.exists():
            # Create only this missing leaf; existing Chrome parent directories are not changed.
            owned(parent.parent, directory=True)
            mkdir_private(parent)
        # Three independent atomic files; not a fictitious cross-file transaction.
        # Keep broker stopped through all replacements. Restore retained backup if any stage fails.
        atomic(host_path, encoded(prepared[1]), snapshots[1][1])
        atomic(manifest_install, encoded(prepared[2]), snapshots[2][1])
        atomic(config_path, encoded(prepared[0]), original)
        print(json.dumps(dict(applied=True, restarted=False, productionQualified=False, backup=str(backup),
                              socketRoot=str(socket_root), enrollmentRoot=str(enrollment), extensionOrigin=prepared[1]['extensionOrigin'])))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Report only locations in this trusted source, never exception text or
        # subprocess output: those may contain verifier/resource secret details.
        frames = traceback.extract_tb(error.__traceback__)
        locations = [f'{frame.name}:{frame.lineno}' for frame in frames
                     if Path(frame.filename).resolve() == Path(__file__).resolve()]
        location = ' > '.join(locations[-8:]) or 'unknown-stage'
        sys.exit(f'Chrome enrollment failed ({type(error).__name__}; {location}); '
                 'secret details and command output withheld. No runtime restart was performed.')
