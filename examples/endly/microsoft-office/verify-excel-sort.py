"""Read-only fixture check: Sheet1 C3:G7 sorted by Region A to Z, no GUI proof."""
import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path

spec = importlib.util.spec_from_file_location('save_copy', Path(__file__).with_name('verify-save-as-copy.py'))
styles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(styles)
v = styles.v
N = v.NS
ORDER = ['East', 'North', 'South', 'West']


def cells(root):
    result, rows = {}, set()
    for row in root.findall(N + 'sheetData/' + N + 'row'):
        number = row.get('r')
        if number in rows:
            raise ValueError('Duplicate worksheet row')
        rows.add(number)
        for cell in row.findall(N + 'c'):
            ref = cell.get('r', '')
            match = re.fullmatch(r'[A-Z]+([1-9][0-9]*)', ref)
            if ref in result or not match or match[1] != number:
                raise ValueError('Ambiguous cell coordinates')
            result[ref] = cell
    return result


def regional_rows(parts, root):
    strings = v.xml(parts['xl/sharedStrings.xml']).findall(N + 'si')
    data, regions = cells(root), {}
    for row in range(4, 8):
        label = data['C' + str(row)]
        if label.get('t') != 's' or label.find(N + 'f') is not None:
            raise ValueError('Expected shared-string Region label')
        index = int(label.findtext(N + 'v'))
        if index < 0 or index >= len(strings):
            raise ValueError('Invalid shared-string index')
        name = ''.join(strings[index].itertext())
        if name not in ORDER or name in regions:
            raise ValueError('Expected four distinct fixture regions')
        regions[name] = row
        for column, formula in [('F', f'D{row}-E{row}'), ('G', f'F{row}/D{row}')]:
            node = data[column + str(row)].find(N + 'f')
            if node is None or node.attrib or node.text != formula:
                raise ValueError('Unsupported or changed regional formula')
        for column in 'DE':
            if data[column + str(row)].find(N + 'f') is not None:
                raise ValueError('Expected literal revenue and cost')
    return data, regions


def verify(before, after, baseline_sha256):
    old, old_hash = v.package(before)
    new, new_hash = v.package(after)
    if old_hash != baseline_sha256:
        raise ValueError('Original SHA256 differs from recorded baseline')
    if set(old) != set(new):
        raise ValueError('Package inventory changed')
    old_sheets, new_sheets = v.sheets(old), v.sheets(new)
    if list(old_sheets.items()) != list(new_sheets.items()) or 'Sheet1' not in old_sheets:
        raise ValueError('Worksheet identity or order changed')
    path = old_sheets['Sheet1']
    before_root, after_root = v.xml(old[path]), v.xml(new[path])
    original, original_rows = regional_rows(old, before_root)
    _, saved_rows = regional_rows(new, after_root)
    if list(saved_rows) != ORDER:
        raise ValueError('Saved regional rows are not Region A to Z')
    if list(original_rows) == ORDER:
        raise ValueError('Baseline already sorted; this case requires changed order')
    expected = copy.deepcopy(before_root)
    expected_cells = cells(expected)
    for destination, region in enumerate(ORDER, 4):
        source = original_rows[region]
        for column in 'CDEFG':
            replacement = copy.deepcopy(original[column + str(source)])
            replacement.set('r', column + str(destination))
            formula = replacement.find(N + 'f')
            if formula is not None:
                formula.text = f'D{destination}-E{destination}' if column == 'F' else f'F{destination}/D{destination}'
            target = expected_cells[column + str(destination)]
            target.attrib.clear()
            target.attrib.update(replacement.attrib)
            target.text = replacement.text
            target[:] = list(replacement)
    if v.content(expected) != v.content(after_root):
        raise ValueError('Row association, formulas, caches, styles or outside-range content changed')
    for name, sheet_path in old_sheets.items():
        if name != 'Sheet1' and v.content(v.xml(old[sheet_path])) != v.content(v.xml(new[sheet_path])):
            raise ValueError('Other worksheet changed: ' + name)
    if styles.resolved_styles(old['xl/styles.xml']) != styles.resolved_styles(new['xl/styles.xml']):
        raise ValueError('Style semantics changed')
    allowed = set(old_sheets.values()) | {'xl/styles.xml'}
    for name in old.keys() - allowed:
        if old[name] != new[name]:
            raise ValueError('Protected package part changed: ' + name)
    return {'beforeSHA256': old_hash, 'afterSHA256': new_hash, 'range': 'Sheet1!C3:G7',
            'key': 'Region', 'order': ORDER, 'savedSortVerified': True,
            'formulasCachesAndRowAssociationsPreserved': True,
            'outsideRangeAndOtherSheetsPreserved': True, 'protectedPackagePartsPreserved': True,
            'guiExecutionProved': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before')
    parser.add_argument('after')
    parser.add_argument('--baseline-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.before, args.after, args.baseline_sha256), indent=2))
