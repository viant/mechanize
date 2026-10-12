"""Synthetic ZIP/XML verifier tests only; never Office GUI insertion evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

_spec = importlib.util.spec_from_file_location("word_table_verifier", Path(__file__).with_name("verify-word-table.py"))
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
MATRIX = [["Metric", "Q1", "Q2"], ["Revenue", "17", "23"], ["Margin", "40%", "42%"]]


def table(matrix=MATRIX):
    grid = '<w:tblGrid>' + '<w:gridCol w:w="2400"/>' * len(matrix[0]) + '</w:tblGrid>'
    rows = []
    for row in matrix:
        cells = []
        for value in row:
            paragraphs = ''.join('<w:p><w:r><w:t xml:space="preserve">' + escape(text) + '</w:t></w:r></w:p>' for text in value.split('\n'))
            cells.append('<w:tc><w:tcPr><w:tcW w:w="2400" w:type="dxa"/></w:tcPr>' + paragraphs + '</w:tc>')
        rows.append('<w:tr>' + ''.join(cells) + '</w:tr>')
    return '<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/></w:tblPr>' + grid + ''.join(rows) + '</w:tbl>'


def parts(added=None, index=1, existing=None):
    paragraphs = [
        '<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="28"/></w:rPr><w:t>Preserved heading</w:t></w:r></w:p>',
        '<w:p><w:r><w:rPr><w:i/></w:rPr><w:t>Preserved adjacent paragraph</w:t></w:r></w:p>']
    if existing is not None:
        paragraphs.insert(1, existing)
    if added is not None:
        paragraphs.insert(index, added)
    section = '<w:sectPr><w:headerReference w:type="default" r:id="h1"/><w:footerReference w:type="default" r:id="f1"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
    return {
        '[Content_Types].xml': b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        'word/document.xml': (f'<w:document xmlns:w="{W}" xmlns:r="{R}"><w:body>' + ''.join(paragraphs) + section + '</w:body></w:document>').encode(),
        'word/styles.xml': f'<w:styles xmlns:w="{W}"><w:style w:type="table" w:styleId="TableGrid"/><w:style w:type="paragraph" w:styleId="Heading1"><w:rPr><w:sz w:val="28"/></w:rPr></w:style></w:styles>'.encode(),
        'word/settings.xml': f'<w:settings xmlns:w="{W}"><w:zoom w:percent="100"/><w:rsids><w:rsid w:val="1"/></w:rsids></w:settings>'.encode(),
        'word/header1.xml': f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>Header preserved</w:t></w:r></w:p></w:hdr>'.encode(),
        'word/footer1.xml': f'<w:ftr xmlns:w="{W}"><w:p><w:r><w:t>Footer preserved</w:t></w:r></w:p></w:ftr>'.encode(),
        'word/_rels/document.xml.rels': ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="h1" Type="' + R + '/header" Target="header1.xml"/>'
            '<Relationship Id="f1" Type="' + R + '/footer" Target="footer1.xml"/></Relationships>').encode(),
        'word/media/image1.png': b'public-synthetic-image',
        'docProps/app.xml': b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Pages>1</Pages><Words>4</Words></Properties>',
    }


class TablePreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original = Path(self.temp.name) / 'original.docx'
        self.saved = Path(self.temp.name) / 'saved.docx'
        self.expected = Path(self.temp.name) / 'expected.json'
        self.expected.write_text(json.dumps(MATRIX), encoding='utf-8')
        self.write(self.original, parts())

    def write(self, path, values):
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in values.items():
                archive.writestr(name, value)

    def check(self, values, expected=MATRIX, index=1, baseline=None):
        self.write(self.saved, values)
        return verifier.verify(self.original, self.saved, index, expected, baseline)

    def test_exact_single_table_preserves_neighbors_sections_headers_and_package(self):
        pin = hashlib.sha256(self.original.read_bytes()).hexdigest()
        result = self.check(parts(table()), baseline=pin)
        self.assertEqual((result['rowCount'], result['columnCount']), (3, 3))
        self.assertEqual(result['originalTopLevelTableCount'], 0)
        self.assertEqual(result['originalParagraphCount'], 2)
        self.assertTrue(result['originalBodyTextAndFormattingPreserved'])
        self.assertTrue(result['sectionLayoutAndHeaderFooterReferencesPreserved'])
        self.assertTrue(result['protectedPackagePartsPreserved'])
        self.assertEqual(result['authority'], 'independent-file-inspection-only')
        self.assertFalse(result['guiInsertionQualified'])
        self.assertNotIn('Revenue', json.dumps(result))

    def test_preexisting_plain_table_preserved_and_only_one_added(self):
        existing = table([['Existing', 'Unchanged']])
        self.write(self.original, parts(existing=existing))
        result = self.check(parts(table(), index=2, existing=existing), index=2)
        self.assertEqual(result['originalTopLevelTableCount'], 1)
        changed = parts(table(), index=2, existing=existing.replace('Unchanged', 'Modified'))
        with self.assertRaises(ValueError):
            self.check(changed, index=2)

    def test_exact_whitespace_unicode_and_paragraph_boundaries_in_cells(self):
        matrix = [[' leading ', 'é & 東京'], ['line one\nline two', '']]
        self.check(parts(table(matrix)), expected=matrix)
        wrong = copy.deepcopy(matrix)
        wrong[0][0] = wrong[0][0].strip()
        with self.assertRaises(ValueError):
            self.check(parts(table(matrix)), expected=wrong)

    def test_no_extra_displaced_or_replacing_table_accepted(self):
        for values, index in [(parts(), 1), (parts(table() + table()), 1), (parts(table()), 0), (parts(table(), index=0), 1)]:
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.check(values, index=index)
        replaced = parts(table())
        document = verifier.xml(replaced['word/document.xml'])
        document.find(verifier.W + 'body').remove(document.find(verifier.W + 'body')[0])
        replaced['word/document.xml'] = ET.tostring(document)
        with self.assertRaises(ValueError):
            self.check(replaced, index=0)

    def test_wrong_rows_columns_text_and_grid_refused(self):
        for changed in [table().replace('Revenue', 'Different'), table().replace('<w:gridCol w:w="2400"/>', '', 1),
                        table([['Metric', 'Q1'], ['Revenue', '17']]), table(MATRIX[:-1])]:
            with self.subTest(table=changed[:20]), self.assertRaises(ValueError):
                self.check(parts(changed))

    def test_nested_merged_tracked_hidden_and_nontext_cells_are_unsupported(self):
        changes = [
            table().replace('<w:tcPr>', '<w:tcPr><w:gridSpan w:val="2"/>', 1),
            table().replace('<w:tcPr>', '<w:tcPr><w:vMerge w:val="restart"/>', 1),
            table().replace('<w:tcPr>', '<w:tcPr><w:hMerge/>', 1),
            table().replace('<w:tr>', '<w:tr><w:trPr><w:gridBefore w:val="1"/></w:trPr>', 1),
            table().replace('</w:tc>', table([['Nested']]) + '</w:tc>', 1),
            table().replace('<w:tblPr>', '<w:tblPr><w:tblpPr/>', 1),
            table().replace('<w:r>', '<w:r><w:rPr><w:vanish/></w:rPr>', 1),
            table().replace('<w:tcPr>', '<w:tcPr><w:tcPrChange/>', 1),
            table().replace('<w:r>', '<w:r><w:drawing/>', 1),
            table().replace('<w:r>', '<w:r><w:br w:type="page"/>', 1),
            table().replace('<w:p>', '<w:p><w:fldSimple w:instr="private-field-canary"/>', 1),
            table().replace('<w:p>', '<w:p><w:pPr><w:numPr/></w:pPr>', 1),
            table().replace('<w:tblPr>', '<w:tblPr><w:t>ignored-text</w:t>', 1),
        ]
        for changed in changes:
            with self.subTest(table=changed[:20]), self.assertRaises(ValueError):
                self.check(parts(changed))
        with self.assertRaises(ValueError):
            self.check(parts('<w:sdt><w:sdtContent>' + table() + '</w:sdtContent></w:sdt>'))

    def test_neighbor_text_runs_styles_and_order_must_survive(self):
        for before, after in [(b'Preserved heading', b'Changed heading'), (b'Heading1', b'Normal'),
                              (b'<w:b/>', b'<w:i/>'), (b'w:val="28"', b'w:val="30"'),
                              (b'Preserved adjacent paragraph', b'Changed adjacent paragraph')]:
            changed = parts(table())
            changed['word/document.xml'] = changed['word/document.xml'].replace(before, after, 1)
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.check(changed)
        changed = parts(table())
        document = verifier.xml(changed['word/document.xml'])
        body = document.find(verifier.W + 'body')
        first, last = body[0], body[2]
        body.remove(first); body.remove(last); body.insert(0, last); body.insert(2, first)
        changed['word/document.xml'] = ET.tostring(document)
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_layout_refs_protected_styles_settings_binary_and_inventory_cannot_change(self):
        mutations = [
            ('word/document.xml', b'12240', b'11900'), ('word/document.xml', b'1440', b'720'),
            ('word/document.xml', b'r:id="h1"', b'r:id="different"'),
            ('word/_rels/document.xml.rels', b'header1.xml', b'header2.xml'),
            ('word/header1.xml', b'Header preserved', b'Changed header'),
            ('word/footer1.xml', b'Footer preserved', b'Changed footer'),
            ('word/styles.xml', b'w:val="28"', b'w:val="30"'),
            ('word/settings.xml', b'100', b'80'), ('docProps/app.xml', b'<Pages>1', b'<Pages>2'),
            ('word/media/image1.png', b'public', b'changed'),
        ]
        for name, before, after in mutations:
            changed = parts(table()); changed[name] = changed[name].replace(before, after)
            with self.subTest(part=name), self.assertRaises(ValueError):
                self.check(changed)
        for add in [True, False]:
            changed = parts(table())
            if add:
                changed['word/added.xml'] = b'<added/>'
            else:
                changed.pop('word/header1.xml')
            with self.assertRaises(ValueError):
                self.check(changed)

    def test_only_known_volatile_revision_properties_and_attribute_order_can_change(self):
        changed = parts(table())
        changed['word/document.xml'] = changed['word/document.xml'].replace(b'<w:p>', b'<w:p w:rsidR="synthetic-revision">')
        changed['word/settings.xml'] = changed['word/settings.xml'].replace(b'w:val="1"', b'w:val="2"')
        changed['docProps/app.xml'] = changed['docProps/app.xml'].replace(b'<Words>4', b'<Words>22')
        changed['word/styles.xml'] = changed['word/styles.xml'].replace(b'w:type="table" w:styleId="TableGrid"', b'w:styleId="TableGrid" w:type="table"')
        self.check(changed)

    def test_baseline_pin_matrix_and_index_validation(self):
        for pin in ['0' * 64, 'A' * 64, 'not-a-digest']:
            with self.assertRaises(ValueError):
                self.check(parts(table()), baseline=pin)
        for matrix in [[], [[]], [['one'], ['two', 'three']], [[1]], {'table': MATRIX}, [['x' * (verifier.MAX_EXPECTED + 1)]], [['\x00']]]:
            with self.assertRaises(ValueError):
                self.check(parts(table()), expected=matrix)
        for index in [-1, True, 1.0, 3, 4096]:
            with self.assertRaises(ValueError):
                self.check(parts(table()), index=index)

    def test_duplicate_unsafe_names_nonregular_and_oversized_xml_refused(self):
        for name in ['WORD/DOCUMENT.XML', '../private.xml', 'word/../private.xml', '/absolute.xml',
                     'word\\private.xml', 'C:private.xml', 'word//extra.xml', 'word/./extra.xml', 'word/control\x01.xml']:
            changed = parts(table()); changed[name] = b'<fixture/>'
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(changed)
        self.write(self.saved, parts(table()))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.saved, 'a') as archive:
                archive.writestr('word/document.xml', parts(table())['word/document.xml'])
        with self.assertRaises(ValueError):
            verifier.verify(self.original, self.saved, 1, MATRIX)
        for file_type in [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR]:
            self.write(self.saved, parts(table()))
            with zipfile.ZipFile(self.saved, 'a') as archive:
                entry = zipfile.ZipInfo('word/nonregular-part')
                entry.create_system = 3; entry.external_attr = (file_type | 0o600) << 16
                archive.writestr(entry, b'public-fixture')
            with self.assertRaises(ValueError):
                verifier.verify(self.original, self.saved, 1, MATRIX)
        changed = parts(table()); changed['word/header1.xml'] = b'<' + b'x' * verifier.MAX_XML
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_all_xml_parts_must_be_well_formed_bounded_and_entity_free(self):
        for bad in [b'<broken>', b'<!DOCTYPE x [<!ENTITY secret "private-canary">]><x>&secret;</x>',
                    '<?xml version="1.0" encoding="UTF-16"?><x/>'.encode('utf-16'),
                    (b'<x>' * 130) + (b'</x>' * 130)]:
            original = parts(); saved = parts(table())
            original['word/header1.xml'] = saved['word/header1.xml'] = bad
            self.write(self.original, original)
            with self.assertRaises(ValueError):
                self.check(saved)

    def test_cli_reads_only_and_never_prints_document_or_matrix_contents(self):
        matrix = [['private-document-content-canary']]
        self.expected.write_text(json.dumps(matrix), encoding='utf-8')
        self.write(self.saved, parts(table(matrix)))
        paths = [self.original, self.saved, self.expected]
        before = [path.read_bytes() for path in paths]
        command = [sys.executable, str(Path(verifier.__file__)), str(self.original), str(self.saved),
                   str(self.expected), '--insertion-index', '1']
        success = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(success.returncode, 0)
        self.assertNotIn(matrix[0][0], success.stdout + success.stderr)
        self.assertFalse(json.loads(success.stdout)['guiInsertionQualified'])
        self.assertEqual(before, [path.read_bytes() for path in paths])
        self.expected.write_text(json.dumps([['different-private-canary']]), encoding='utf-8')
        failed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stdout), {'verified': False, 'error': 'DOCX table verification failed'})
        self.assertEqual(failed.stderr, '')
        self.assertNotIn('private-canary', failed.stdout)


if __name__ == '__main__':
    unittest.main()
