"""Synthetic saved-package checks; deliberately no app or desktop access."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('sort_verifier', Path(__file__).with_name('verify-excel-sort.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'


def fixture(order):
    data = {'North': (0, 1200, 800, 400, '0.33333333333333331'),
            'South': (1, 1800, 1000, 800, '0.44444444444444442'),
            'East': (2, 900, 600, 300, '0.33333333333333331'),
            'West': (3, 1500, 1100, 400, '0.26666666666666666')}
    rows = ['<row r="3"><c r="C3" t="inlineStr"><is><t>Region</t></is></c></row>']
    for row, name in enumerate(order, 4):
        index, revenue, cost, profit, margin = data[name]
        rows.append(f'<row r="{row}"><c r="C{row}" t="s"><v>{index}</v></c>'
                    f'<c r="D{row}"><v>{revenue}</v></c><c r="E{row}"><v>{cost}</v></c>'
                    f'<c r="F{row}"><f>D{row}-E{row}</f><v>{profit}</v></c>'
                    f'<c r="G{row}" s="1"><f>F{row}/D{row}</f><v>{margin}</v></c></row>')
    rows.append('<row r="8"><c r="D8"><f>SUM(D4:D7)</f><v>5400</v></c></row>')
    parts = {
        'xl/workbook.xml': f'<workbook xmlns="{NS}" xmlns:r="{REL}"><sheets><sheet name="Sheet1" sheetId="1" r:id="a"/><sheet name="Sheet2" sheetId="2" r:id="b"/></sheets></workbook>',
        'xl/_rels/workbook.xml.rels': f'<Relationships><Relationship Id="a" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="b" Type="{REL}/worksheet" Target="worksheets/sheet2.xml"/></Relationships>',
        'xl/worksheets/sheet1.xml': f'<worksheet xmlns="{NS}"><sheetData>{"".join(rows)}</sheetData></worksheet>',
        'xl/worksheets/sheet2.xml': f'<worksheet xmlns="{NS}"><sheetData><row r="1"><c r="A1"><f>DATE(2026,10,5)</f><v>46200</v></c></row></sheetData></worksheet>',
        'xl/sharedStrings.xml': f'<sst xmlns="{NS}"><si><t>North</t></si><si><t>South</t></si><si><t>East</t></si><si><t>West</t></si></sst>',
        'xl/styles.xml': f'<styleSheet xmlns="{NS}"><cellXfs count="2"><xf numFmtId="0"/><xf numFmtId="9"/></cellXfs></styleSheet>',
        'xl/charts/chart1.xml': '<chart><formula>Sheet1!$C$4:$C$7</formula></chart>',
        'xl/worksheets/_rels/sheet1.xml.rels': '<Relationships><Relationship Id="chart" Target="../drawings/drawing1.xml"/></Relationships>',
        'docProps/core.xml': '<core/>',
    }
    return {key: value.encode() for key, value in parts.items()}


class SortPreservationTests(unittest.TestCase):
    def setUp(self):
        self.before = fixture(['North', 'South', 'East', 'West'])
        self.after = fixture(v.ORDER)

    def check(self, before=None, after=None, baseline=None):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / name for name in ['before.xlsx', 'after.xlsx']]
            for path, parts in zip(paths, [before or self.before, after or self.after]):
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, data in parts.items():
                        archive.writestr(name, data)
            hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
            try:
                return v.verify(*paths, baseline or hashes[0])
            finally:
                self.assertEqual(hashes, [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths])

    def test_valid_sort_preserves_all_associations_without_claiming_gui(self):
        result = self.check()
        self.assertTrue(result['savedSortVerified'])
        self.assertFalse(result['guiExecutionProved'])

    def test_unsorted_and_already_sorted_rejected(self):
        for before, after in [(self.before, self.before), (self.after, self.after)]:
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.check(before, after)

    def test_custom_format_id_renumbering_and_sheet_views_allowed(self):
        before, after = copy.deepcopy(self.before), copy.deepcopy(self.after)
        template = '<styleSheet xmlns="%s"><numFmts count="1"><numFmt numFmtId="ID" formatCode="yyyy-mm-dd"/></numFmts><cellXfs count="2"><xf numFmtId="0"/><xf numFmtId="ID"/></cellXfs></styleSheet>' % NS
        before['xl/styles.xml'] = template.replace('ID', '165').encode()
        after['xl/styles.xml'] = template.replace('ID', '164').encode()
        after['xl/worksheets/sheet1.xml'] = after['xl/worksheets/sheet1.xml'].replace(b'<sheetData>', b'<sheetViews><sheetView workbookViewId="0"/></sheetViews><sheetData>')
        self.assertTrue(self.check(before, after)['savedSortVerified'])

    def test_wrong_baseline_rejected(self):
        with self.assertRaisesRegex(ValueError, 'baseline'):
            self.check(baseline='0' * 64)

    def test_cell_mutations_rejected(self):
        changes = [
            (b'<v>900</v>', b'<v>1200</v>'),  # detached revenue
            (b'<f>D4-E4</f>', b'<f>D6-E6</f>'),  # stale formula reference
            (b'<v>300</v>', b'<v>301</v>'),  # changed cache
            (b'r="G4" s="1"', b'r="G4" s="0"'),
            (b'<t>Region</t>', b'<t>Other</t>'),
            (b'<v>5400</v>', b'<v>5300</v>'),
            (b'<f>SUM(D4:D7)</f>', b'<f>SUM(D4:D6)</f>'),
            (b'<v>2</v>', b'<v>0</v>'),  # duplicate region
            (b'<f>D4-E4</f>', b'<f t="shared">D4-E4</f>'),
            (b'r="D4"', b'r="D5"'),
        ]
        for old, new in changes:
            after = copy.deepcopy(self.after)
            after['xl/worksheets/sheet1.xml'] = after['xl/worksheets/sheet1.xml'].replace(old, new, 1)
            with self.subTest(change=new), self.assertRaises(ValueError):
                self.check(after=after)

    def test_protected_parts_and_other_sheets_rejected(self):
        for part in ['xl/worksheets/sheet2.xml', 'xl/charts/chart1.xml',
                     'xl/worksheets/_rels/sheet1.xml.rels', 'xl/styles.xml', 'docProps/core.xml']:
            after = copy.deepcopy(self.after)
            after[part] = after[part].replace(b'46200', b'46201') if 'sheet2' in part else after[part].replace(b'/>', b' changed="yes"/>', 1).replace(b'</chart>', b'<change/></chart>')
            with self.subTest(part=part), self.assertRaises(ValueError):
                self.check(after=after)

    def test_inventory_addition_and_removal_rejected(self):
        for added in [True, False]:
            after = copy.deepcopy(self.after)
            if added:
                after['xl/externalLinks/link.xml'] = b'<link/>'
            else:
                del after['xl/charts/chart1.xml']
            with self.subTest(added=added), self.assertRaises(ValueError):
                self.check(after=after)


if __name__ == '__main__':
    unittest.main()
