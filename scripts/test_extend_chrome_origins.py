import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('extend_origins', Path(__file__).with_name('extend-chrome-origins.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OriginExtensionTests(unittest.TestCase):
    def setUp(self):
        self.extension = 'a' * 32
        self.principal = dict(issuer='fixture', subject='fixture-owner', namespace='fixture-namespace',
                              clientId='fixture-client', scopes=['desktop:observe', 'desktop:control'])
        self.config = dict(unrelated={'keep': True}, keys={'fixtureOnly': True},
                           users=[dict(subject='fixture-owner', desktopAccess=True)],
                           chrome=dict(fixtureEnrollment=False, socketPath='/fixture/socket',
                                       grants=[dict(principal=copy.deepcopy(self.principal),
                                                    extensionOrigin='chrome-extension://' + self.extension + '/',
                                                    origins=['http://127.0.0.1:18771'],
                                                    credentialResource={'fixtureOnly': True})]))

    def test_only_origins_change(self):
        before = copy.deepcopy(self.config)
        updated, count = module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])
        self.assertEqual(count, 1)
        self.assertEqual(self.config, before)
        self.assertEqual(updated['chrome']['grants'][0]['origins'], ['http://127.0.0.1:18771', 'https://bank.example.test'])
        updated['chrome']['grants'][0]['origins'] = before['chrome']['grants'][0]['origins']
        self.assertEqual(updated, before)

    def test_noop_preserves_config(self):
        self.config['chrome']['grants'][0]['origins'].append('https://bank.example.test')
        updated, count = module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])
        self.assertEqual((updated, count), (self.config, 0))
    def test_explicit_all_websites_preserves_credentials_and_requires_ceiling(self):
        before = copy.deepcopy(self.config)
        updated, count = module.prepare(self.config, self.principal, self.extension, all_websites=True)
        self.assertEqual(count, 1)
        self.assertEqual(self.config, before)
        grant = updated['chrome']['grants'][0]
        self.assertEqual(grant['origins'], [])
        self.assertTrue(grant.pop('allWebsites'))
        grant['origins'] = before['chrome']['grants'][0]['origins']
        self.assertEqual(updated, before)
        self.config['users'][0]['desktopAccess'] = False
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, all_websites=True)
    def test_all_websites_rejects_mixed_scope_and_is_idempotent(self):
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'], True)
        self.config['chrome']['grants'][0].update(allWebsites=True, origins=[])
        self.assertEqual(module.prepare(self.config, self.principal, self.extension, all_websites=True), (self.config, 0))
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])

    def test_rejects_noncanonical_origins(self):
        for value in ['http://bank.example.test', 'https://bank.example.test/', 'https://bank.example.test?q=x',
                      'https://bank.example.test#x', 'https://user:pass@bank.example.test', 'https://BANK.example.test',
                      'https://*.example.test', 'https://bank.example.test:443', 'https://bank.example.test:99999',
                      'https://bank.example.test\\evil', 'https://bank.example.test\n', 'https://bank.example.test:',
                      'https://bank.example.test:0443', 'https://bank.example.test:00080']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.https_origin(value)

    def test_rejects_foreign_or_ambiguous_channel(self):
        for mode in ('client', 'namespace', 'extension', 'duplicate'):
            config = copy.deepcopy(self.config)
            if mode in ('client', 'namespace'):
                config['chrome']['grants'][0]['principal']['clientId' if mode == 'client' else 'namespace'] = 'other'
            elif mode == 'extension':
                config['chrome']['grants'][0]['extensionOrigin'] = 'chrome-extension://' + 'b' * 32 + '/'
            else:
                config['chrome']['grants'].append(copy.deepcopy(config['chrome']['grants'][0]))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                module.prepare(config, self.principal, self.extension, ['https://bank.example.test'])

    def test_user_ceiling_and_scopes(self):
        self.config['users'][0]['desktopAccess'] = False
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])
        self.config['users'][0]['webOrigins'] = ['https://bank.example.test']
        self.assertEqual(module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])[1], 1)
        self.principal['scopes'] = ['desktop:observe']
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])

    def test_bounds_and_fixture(self):
        for origins in ([], ['https://bank.example.test'] * 2, ['https://a%d.example.test' % i for i in range(21)]):
            with self.assertRaises(ValueError):
                module.prepare(self.config, self.principal, self.extension, origins)
        self.config['chrome']['fixtureEnrollment'] = True
        with self.assertRaises(ValueError):
            module.prepare(self.config, self.principal, self.extension, ['https://bank.example.test'])


if __name__ == '__main__':
    unittest.main()
