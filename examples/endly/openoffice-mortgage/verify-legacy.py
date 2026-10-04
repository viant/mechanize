#!/usr/bin/env python3
"""Read-only checks for the DOC/XLS copies created through OpenOffice UI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import olefile
import xlrd
from xlrd.formula import decompile_formula, FMLA_TYPE_CELL


def cell(sheet, address):
    return sheet.cell_value(int(address[1:]) - 1, ord(address[0]) - 65)


def formula_map(path, book, sheet_index=0):
    with olefile.OleFileIO(path) as compound:
        raw = compound.openstream('Workbook').read()
    def records(start):
        pos = start
        while pos + 4 <= len(raw):
            code, size = struct.unpack_from('<HH', raw, pos)
            assert pos + 4 + size <= len(raw), 'Truncated BIFF record'
            payload = raw[pos + 4:pos + 4 + size]
            pos += 4 + size
            yield code, payload
            if code == 0x000A:
                break
    sheet_offsets = []
    for code, value in records(0):
        if code == 0x0085:
            assert len(value) >= 4, 'Truncated BOUNDSHEET record'
            sheet_offsets.append(struct.unpack_from('<I', value)[0])
    assert len(sheet_offsets) == book.nsheets, 'BOUNDSHEET count differs from workbook sheet count'
    assert isinstance(sheet_index, int) and 0 <= sheet_index < len(sheet_offsets), 'Invalid formula sheet index'
    sheet_offset = sheet_offsets[sheet_index]
    assert 0 <= sheet_offset < len(raw), 'BOUNDSHEET offset outside workbook stream'
    result = {}
    for code, payload in records(sheet_offset):
        if code != 0x0006:
            continue
        assert len(payload) >= 22, 'Truncated formula header'
        row, column = struct.unpack_from('<HH', payload)
        size = struct.unpack_from('<H', payload, 20)[0]
        assert len(payload) >= 22 + size, 'Truncated formula tokens'
        formula = decompile_formula(book, payload[22:22 + size], size,
                                    FMLA_TYPE_CELL, browx=row, bcolx=column)
        assert formula is not None and column < 26, 'Unqualified formula encoding'
        address = f'{chr(65 + column)}{row + 1}'
        assert address not in result, 'Duplicate formula cell'
        result[address] = re.sub(r'(?<=\d)\.0+\b', '', formula).replace(' ', '')
    return result


def fingerprint(path):
    content = path.read_bytes()
    assert content[:8] == bytes.fromhex('D0CF11E0A1B11AE1'), 'Expected compound binary file'
    return {'path': str(path), 'bytes': len(content),
            'sha256': hashlib.sha256(content).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    fixture = json.loads(Path(__file__).with_name('data.json').read_text())
    stem = 'Mortgage Rates 2026-10-01'
    doc, xls = (args.directory / (stem + ext) for ext in ('.doc', '.xls'))
    doc_info, xls_info = fingerprint(doc), fingerprint(xls)
    text = subprocess.run(['textutil', '-convert', 'txt', '-stdout', str(doc)],
                          check=True, capture_output=True, text=True).stdout
    assert ' '.join(fixture['writer_summary'].split()) in ' '.join(text.split()), 'Word summary mismatch'
    book = xlrd.open_workbook(str(xls), on_demand=True)
    try:
        assert book.biff_version == 80, 'Expected Excel 97 BIFF8'
        sheet = book.sheet_by_index(0)
        assert sheet.name == 'Sheet1'
        assert sheet.row_values(0)[:4] == fixture['calc_table_plan']['columns']
        for row, key in ((2, 'prior'), (3, 'current')):
            rate = fixture['rates'][key]
            assert xlrd.xldate_as_datetime(cell(sheet, f'A{row}'), book.datemode).date().isoformat() == rate['date']
            for column, term in (('B', '30_year_fixed'), ('C', '15_year_fixed')):
                assert abs(cell(sheet, f'{column}{row}') - rate[term]) < 1e-12
        for address, expected in fixture['calc_table_plan']['expected_formula_results'].items():
            assert abs(cell(sheet, address) - expected) < 1e-12, address + ': cached result mismatch'
        expected = {address: value.lstrip('=').replace(';', ',')
                    for address, value in fixture['calc_table_plan']['formulas'].items()}
        assert formula_map(xls, book) == expected, 'Stored XLS formulas mismatch'
        for address, expected in fixture['calc_table_plan']['notes'].items():
            assert cell(sheet, address) == expected, address + ': note mismatch'
    finally:
        book.release_resources()
    print(json.dumps({'verified': True, 'word': doc_info, 'excel': xls_info,
                      'checks': ['Word summary', 'BIFF8', 'headers', 'dates', 'rates',
                                 'cached results', 'stored formulas', 'source notes']}, indent=2))

if __name__ == '__main__':
    main()
