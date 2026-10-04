#!/usr/bin/env python3
"""Read-only verification of the example's GUI-created ODT and ODS artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

NS = {k: 'urn:oasis:names:tc:opendocument:xmlns:' + v + ':1.0'
      for k, v in [('t', 'table'), ('o', 'office'), ('x', 'text')]}

def attr(node, prefix, name):
    return node.get('{' + NS[prefix] + '}' + name)

def read(path, mime):
    with zipfile.ZipFile(path) as archive:
        assert archive.read('mimetype').decode() == mime, str(path) + ': wrong MIME'
        root = ET.fromstring(archive.read('content.xml'))
    return root, {'path': str(path), 'bytes': path.stat().st_size,
                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

def cells(table):
    # Expand only the bounded region under test; ODS may compress empty rows/cells.
    result = {}
    ri = 1
    for row in table.findall('t:table-row', NS):
        repeat = int(attr(row, 't', 'number-rows-repeated') or 1)
        for r in range(ri, min(ri + repeat, 9)):
            ci = 0
            for cell in row:
                count = int(attr(cell, 't', 'number-columns-repeated') or 1)
                for c in range(ci, min(ci + count, 4)):
                    result[f'{chr(65+c)}{r}'] = cell
                ci += count
                if ci >= 4:
                    break
        ri += repeat
        if ri > 8:
            break
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    fixture = json.loads(Path(__file__).with_name('data.json').read_text())
    root, writer = read(args.directory / fixture['intended_output']['writer_file'],
                        'application/vnd.oasis.opendocument.text')
    assert fixture['writer_summary'] in ''.join(root.itertext()), 'Writer summary missing'
    root, calc = read(args.directory / fixture['intended_output']['calc_file'],
                      'application/vnd.oasis.opendocument.spreadsheet')
    table = root.find('.//t:table', NS)
    assert table is not None, 'No Calc sheet'
    c = cells(table)
    for address, expected in {'A1': 'Date', 'B1': '30yr fixed', 'C1': '15yr fixed',
                              'D1': 'Spread bp', 'A4': 'Change bp'}.items():
        assert address in c and ''.join(c[address].itertext()) == expected, address + ': text mismatch'
    for address, expected in {'A2': '2026-09-24', 'A3': '2026-10-01'}.items():
        assert (attr(c[address], 'o', 'date-value') or ''.join(c[address].itertext())) == expected, address + ': date mismatch'
    for address, expected in {'B2': .0703, 'C2': .0642, 'B3': .0728, 'C3': .066,
                              'D2': 61, 'D3': 68, 'B4': 25, 'C4': 18, 'D4': 7}.items():
        assert address in c, address + ': missing'
        actual = attr(c[address], 'o', 'value')
        assert actual is not None and abs(float(actual) - expected) < 1e-10, address + ': numeric result mismatch'
    expected_formulas = {'D2': 'ROUND(([.B2]-[.C2])*10000;0)',
                         'D3': 'ROUND(([.B3]-[.C3])*10000;0)',
                         'B4': 'ROUND(([.B3]-[.B2])*10000;0)',
                         'C4': 'ROUND(([.C3]-[.C2])*10000;0)', 'D4': '[.D3]-[.D2]'}
    for address, expected in expected_formulas.items():
        formula = attr(c[address], 't', 'formula') or ''
        assert formula.partition(':=')[2] == expected, address + ': stored formula mismatch: ' + formula
    assert fixture['source']['url'] in ''.join(c['A6'].itertext()), 'Source URL missing'
    print(json.dumps({'verified': True, 'writer': writer, 'calc': calc,
                      'checks': ['summary', 'headers', 'dates', 'rates', 'stored formulas', 'cached results', 'source URL']}, indent=2))

if __name__ == '__main__':
    main()
