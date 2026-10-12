"""Synthetic tests of the narrow custom-number-format alias normalization."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('save_as_verifier',Path(__file__).with_name('verify-save-as-copy.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class StylePreservationTests(unittest.TestCase):
    def style(self,id=165,code='yyyy-mm-dd',reference=None):
        ns=v.v.NS[1:-1]
        return f'<styleSheet xmlns="{ns}"><numFmts count="1"><numFmt numFmtId="{id}" formatCode="{code}"/></numFmts><fonts count="1"><font><sz val="12"/></font></fonts><cellXfs count="1"><xf numFmtId="{id if reference is None else reference}" fontId="0"/></cellXfs></styleSheet>'.encode()
    def testCustomNumberFormatRenumberingPreservesMeaning(self):
        self.assertEqual(v.resolved_styles(self.style(165)),v.resolved_styles(self.style(164)))
    def testChangedFormatFontOrStyleReferenceIsNotHidden(self):
        original=v.resolved_styles(self.style())
        for changed in [self.style(code='mm/dd/yyyy'),self.style().replace(b'val="12"',b'val="14"'),self.style(reference=0)]:
            with self.subTest(changed=changed):self.assertNotEqual(original,v.resolved_styles(changed))
    def testDanglingAndDuplicateCustomDefinitionsRejected(self):
        with self.assertRaises(ValueError):v.resolved_styles(self.style(reference=166))
        duplicate=self.style().replace(b'</numFmts>',b'<numFmt numFmtId="165" formatCode="0.00"/></numFmts>')
        with self.assertRaises(ValueError):v.resolved_styles(duplicate)
    def testBuiltinIdCannotMasqueradeAsCustomAlias(self):
        with self.assertRaises(ValueError):v.resolved_styles(self.style(id=14))

if __name__=='__main__':unittest.main()
