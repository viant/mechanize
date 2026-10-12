import base64
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('custody_builder', Path(__file__).with_name('build-custody-migration.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class CustodyBuildTests(unittest.TestCase):
    def fixture(self):
        value = {key: 'fixture' for key in builder.REQUIRED_FIELDS}
        value.update(version=1, session='a'*64, namespace='b'*64, expectedUID=501,
                     config={'path': '/private/config', 'sha256': 'c'*64},
                     resources=[{'path': '/private/key', 'sha256': 'd'*64}])
        return value

    def test_relocation_v2_appends_new_path_and_rejects_version_confusion(self):
        value=self.fixture();value['version']=2;value['newCanonicalExecutable']='/Users/fixture/Applications/Mechanize.app/Contents/Helpers/mechanize'
        actual=json.loads(base64.b64decode(builder.encode_enrollment(value)))
        self.assertEqual(list(actual)[-1],'newCanonicalExecutable')
        self.assertEqual(actual['canonicalExecutable'],value['canonicalExecutable'])
        value['version']=1
        with self.assertRaises(ValueError):builder.encode_enrollment(value)
        value['version']=2;value['newCanonicalExecutable']='/unreviewed/broker'
        with self.assertRaises(ValueError):builder.encode_enrollment(value)

    def test_canonical_public_only_enrollment(self):
        value = self.fixture()
        actual = json.loads(base64.b64decode(builder.encode_enrollment(value)))
        self.assertEqual(actual, value)
        self.assertEqual(list(actual), list(builder.REQUIRED_FIELDS))

    def test_preparation_mode_is_frozen_closed_metadata(self):
        value = self.fixture()
        value['preparation'] = {'mutationExecutable': '/private/mutation', 'mutationRequirement': 'reviewed pin', 'mutationSHA256': 'e'*64, 'runtimeManifestSHA256': 'f'*64}
        actual = json.loads(base64.b64decode(builder.encode_enrollment(value)))
        self.assertEqual(list(actual['preparation']), ['mutationExecutable', 'mutationRequirement', 'mutationSHA256', 'runtimeManifestSHA256'])
        value['preparation']['approved'] = True
        with self.assertRaises(ValueError):
            builder.encode_enrollment(value)

    def test_installer_mode_binds_only_a_pinned_plan_resource(self):
        value = self.fixture()
        value['installPlan'] = {'path': '/private/install-plan.json', 'sha256': 'e'*64}
        actual = json.loads(base64.b64decode(builder.encode_enrollment(value)))
        self.assertEqual(actual['installPlan'], value['installPlan'])
        value['installPlan']['approved'] = True
        with self.assertRaises(ValueError):
            builder.encode_enrollment(value)
        value = self.fixture()
        value['installPlan'] = {'path': '/private/install-plan.json', 'sha256': 'e'*64}
        value['expectedIdentity'] = 'Zml4dHVyZQ=='
        with self.assertRaises(ValueError):
            builder.encode_enrollment(value)

    def test_claim_secret_and_unknown_fields_rejected(self):
        for key in ['nativeHuman', 'approval', 'credential', 'keys']:
            value = self.fixture()
            value[key] = 'private-canary'
            with self.assertRaises(ValueError):
                builder.encode_enrollment(value)
        value = self.fixture()
        value['resources'][0]['data'] = 'private-canary'
        with self.assertRaises(ValueError):
            builder.encode_enrollment(value)

if __name__ == '__main__':
    unittest.main()
