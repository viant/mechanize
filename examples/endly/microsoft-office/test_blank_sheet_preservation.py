"""Synthetic verifier tests; these files are not GUI qualification evidence."""
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('verifier', Path(__file__).with_name('verify-blank-sheet-preservation.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

class PreservationTests(unittest.TestCase):
    def fixture(self, added=False):
        namespace = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
        relationship = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
        sheets = '<sheet name="Sheet1" sheetId="1" r:id="r1"/>'
        rels = '<Relationship Id="r1" Type="'+relationship+'/worksheet" Target="worksheets/sheet1.xml"/>'
        if added:
            sheets += '<sheet name="Sheet2" sheetId="2" r:id="r2"/>'
            rels += '<Relationship Id="r2" Type="'+relationship+'/worksheet" Target="worksheets/sheet2.xml"/>'
        parts = {'xl/workbook.xml':f'<workbook xmlns="{namespace}" xmlns:r="{relationship}"><sheets>{sheets}</sheets></workbook>'.encode(),
                 'xl/_rels/workbook.xml.rels':('<Relationships>'+rels+'</Relationships>').encode(),
                 'xl/worksheets/sheet1.xml':f'<worksheet xmlns="{namespace}"><sheetViews><sheetView tabSelected="{0 if added else 1}"/></sheetViews><sheetData><row r="1"><c r="A1"><f>SUM(17,23)</f><v>40</v></c></row></sheetData></worksheet>'.encode(),
                 'xl/styles.xml':b'<styles/>','xl/charts/chart1.xml':b'<chart/>','xl/media/image1.png':b'synthetic-image'}
        if added:
            parts['xl/worksheets/sheet2.xml'] = f'<worksheet xmlns="{namespace}"><sheetData/></worksheet>'.encode()
        return parts

    def inspect(self, parts):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder)/'before.xlsx', Path(folder)/'after.xlsx']
            for path, data in zip(paths, [self.fixture(), parts]):
                with zipfile.ZipFile(path,'w') as archive:
                    for name, content in data.items(): archive.writestr(name,content)
            return verifier.verify(*paths,'Sheet2')

    def testSelectionChangesAllowedAndContentPreserved(self):
        self.assertTrue(self.inspect(self.fixture(True))['blankSheetVerified'])

    def testOriginalFormulaResultChartAndStyleChangesRejected(self):
        changes = [('xl/worksheets/sheet1.xml', b'SUM(17,23)', b'SUM(17,24)'),
                   ('xl/worksheets/sheet1.xml',b'<v>40</v>',b'<v>41</v>'),
                   ('xl/charts/chart1.xml', b'<chart/>',b'<changed/>'),
                   ('xl/styles.xml',b'<styles/>',b'<changed/>')]
        for name, before, after in changes:
            with self.subTest(part=name,change=after):
                parts=self.fixture(True);parts[name]=parts[name].replace(before,after)
                with self.assertRaises(ValueError):self.inspect(parts)

    def testNonblankExtraMissingAndExternalSheetsRejected(self):
        parts=self.fixture(True)
        parts['xl/worksheets/sheet2.xml']=parts['xl/worksheets/sheet2.xml'].replace(b'<sheetData/>',b'<sheetData><row><c r="A1"/></row></sheetData>')
        with self.assertRaises(ValueError):self.inspect(parts)
        parts=self.fixture(True);parts['xl/_rels/workbook.xml.rels']=parts['xl/_rels/workbook.xml.rels'].replace(b'Id="r2"',b'Id="r2" TargetMode="External"')
        with self.assertRaises(ValueError):self.inspect(parts)
        with self.assertRaises(ValueError):self.inspect(self.fixture(False))

if __name__=='__main__':unittest.main()
