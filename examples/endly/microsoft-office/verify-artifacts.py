#!/usr/bin/env python3
"""Independently inspect Office GUI outputs without modifying the documents."""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import xml.etree.ElementTree as ET
import zipfile

NS = {'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
REL = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id'


def verify_workbook(path, expected, original_hash=None):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if original_hash and digest != original_hash:
        raise ValueError('workbook hash changed')
    with zipfile.ZipFile(path) as archive:
        strings = []
        if 'xl/sharedStrings.xml' in archive.namelist():
            strings = [''.join(t.text or '' for t in si.findall('.//x:t', NS))
                       for si in ET.fromstring(archive.read('xl/sharedStrings.xml')).findall('x:si', NS)]
        relations = {r.attrib['Id']: r.attrib['Target'] for r in
                     ET.fromstring(archive.read('xl/_rels/workbook.xml.rels'))
                     if r.attrib.get('TargetMode') != 'External'}
        sheets = {}
        for sheet in ET.fromstring(archive.read('xl/workbook.xml')).findall('x:sheets/x:sheet', NS):
            target = relations[sheet.attrib[REL]]
            target = target.lstrip('/') if target.startswith('/') else posixpath.normpath(posixpath.join('xl', target))
            if not target.startswith('xl/worksheets/'):
                continue
            cells = {}
            for cell in ET.fromstring(archive.read(target)).findall('.//x:sheetData/x:row/x:c', NS):
                value = cell.find('x:v', NS)
                text = '' if value is None else value.text or ''
                if cell.attrib.get('t') == 's':
                    text = strings[int(text)]
                elif cell.attrib.get('t') == 'inlineStr':
                    text = ''.join(n.text or '' for n in cell.findall('.//x:t', NS))
                formula = cell.find('x:f', NS)
                cells[cell.attrib['r']] = {'value': text, 'formula': None if formula is None else formula.text}
            sheets[sheet.attrib['name']] = cells
        for name, cells in expected.items():
            for address, value in cells.items():
                actual = sheets.get(name, {}).get(address, {}).get('value')
                if actual != value:
                    raise ValueError(f'{name}!{address}: expected {value!r}, got {actual!r}')
    return {'path': str(path.resolve()), 'sha256': digest, 'sizeBytes': len(data), 'sheets': sheets}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workbook', type=Path, required=True)
    parser.add_argument('--expect', required=True, help='JSON sheet/cell/text mapping')
    parser.add_argument('--workbook-sha256')
    parser.add_argument('--pdf', type=Path)
    parser.add_argument('--pdf-text')
    parser.add_argument('--pdf-pages', type=int)
    args = parser.parse_args()
    report = {'workbook': verify_workbook(args.workbook, json.loads(args.expect), args.workbook_sha256)}
    if args.pdf:
        from pypdf import PdfReader
        reader = PdfReader(args.pdf)
        text = '\n'.join(p.extract_text() or '' for p in reader.pages).strip()
        if args.pdf_text is not None and text != args.pdf_text:
            raise ValueError('PDF text differs from the expected content')
        if args.pdf_pages is not None and len(reader.pages) != args.pdf_pages:
            raise ValueError('PDF page count differs from the expected count')
        report['pdf'] = {'path': str(args.pdf.resolve()), 'pages': len(reader.pages), 'text': text,
                         'sha256': hashlib.sha256(args.pdf.read_bytes()).hexdigest(),
                         'pageSizes': [[float(p.mediabox.width), float(p.mediabox.height)] for p in reader.pages]}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
