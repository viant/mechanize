"""Synthetic preservation fixtures; no GUI execution evidence."""
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

folder=Path(__file__).parent
spec=importlib.util.spec_from_file_location('date_verifier',folder/'verify-date-cell.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
spec=importlib.util.spec_from_file_location('fixtures',folder/'test_blank_sheet_preservation.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class DatePreservationTests(unittest.TestCase):
    def fixture(self,after):
        parts=f.PreservationTests().fixture(True)
        n=v.package_verifier.NS[1:-1]
        styles=f'<styleSheet xmlns="{n}"><numFmts count="{2 if after else 1}"><numFmt numFmtId="164" formatCode="0.00"/>'
        if after:styles+='<numFmt numFmtId="165" formatCode="yyyy-mm-dd"/>'
        styles+=f'</numFmts><cellXfs count="{2 if after else 1}"><xf numFmtId="164"/>'
        if after:styles+='<xf numFmtId="165"/>'
        parts['xl/styles.xml']=(styles+'</cellXfs></styleSheet>').encode()
        if after:parts['xl/worksheets/sheet2.xml']=f'<worksheet xmlns="{n}"><sheetData><row r="1"><c r="A1" s="1"><f>DATE(2026,10,5)</f><v>46300</v></c></row></sheetData></worksheet>'.encode()
        return parts
    def inspect(self,after):
        with tempfile.TemporaryDirectory() as root:
            paths=[Path(root)/'before.xlsx',Path(root)/'after.xlsx']
            for path,parts in zip(paths,[self.fixture(False),after]):
                with zipfile.ZipFile(path,'w') as z:
                    for name,data in parts.items():z.writestr(name,data)
            return v.verify(*paths,'Sheet2','2026-10-05')
    def testDateAndOriginalContentPreserved(self):
        self.assertEqual(self.inspect(self.fixture(True))['serial'],'46300')
    def testWrongDateFormulaSerialAndFormatRejected(self):
        for part,before,after in [('xl/worksheets/sheet2.xml',b'46300',b'46301'),('xl/worksheets/sheet2.xml',b'DATE(2026,10,5)',b'DATE(2026,10,6)'),('xl/styles.xml',b'yyyy-mm-dd',b'mm/dd/yyyy')]:
            with self.subTest(part=part,change=after):
                data=self.fixture(True);data[part]=data[part].replace(before,after)
                with self.assertRaises(ValueError):self.inspect(data)
    def testOriginalFormatAndDataChangesRejected(self):
        for part,before,after in [('xl/styles.xml',b'0.00',b'0%'),('xl/worksheets/sheet1.xml',b'<v>40</v>',b'<v>41</v>'),('xl/charts/chart1.xml',b'<chart/>',b'<changed/>')]:
            with self.subTest(part=part):
                data=self.fixture(True);data[part]=data[part].replace(before,after)
                with self.assertRaises(ValueError):self.inspect(data)
    def testUnexpectedDrawingRejected(self):
        data=self.fixture(True);data['xl/worksheets/sheet2.xml']=data['xl/worksheets/sheet2.xml'].replace(b'</worksheet>',b'<drawing/></worksheet>')
        with self.assertRaises(ValueError):self.inspect(data)

if __name__=='__main__':unittest.main()
