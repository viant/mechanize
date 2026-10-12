"""Read-only independent XLSX verification after GUI blank-sheet insertion."""
import argparse
import copy
import hashlib
import json
import posixpath
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
REL = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'

def package(path):
    raw = Path(path).read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError('Package exceeds inspection bound')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 1000 or len(set(name.casefold() for name in names)) != len(names):
            raise ValueError('Ambiguous package inventory')
        if any(name.startswith('/') or '\\' in name or posixpath.normpath(name) != name or '..' in name.split('/') for name in names):
            raise ValueError('Noncanonical package path')
        if sum(entry.file_size for entry in entries) > 64 * 1024 * 1024 or any(entry.file_size > 16 * 1024 * 1024 for entry in entries):
            raise ValueError('Expanded package exceeds inspection bound')
        parts = {name: archive.read(name) for name in names}
    return parts, hashlib.sha256(raw).hexdigest()

def xml(data):
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('XML entity declarations refused')
    return ET.fromstring(data)

def sheets(parts):
    relationships = xml(parts['xl/_rels/workbook.xml.rels'])
    bindings = {}
    for relation in relationships:
        key = relation.attrib['Id']
        if key in bindings or relation.get('TargetMode') == 'External':
            raise ValueError('Ambiguous or external workbook relationship')
        bindings[key] = relation
    result = {}
    for sheet in xml(parts['xl/workbook.xml']).find(NS+'sheets'):
        name = sheet.attrib['name']
        relation = bindings[sheet.attrib[REL+'id']]
        if name in result or not relation.attrib['Type'].endswith('/worksheet'):
            raise ValueError('Ambiguous or non-worksheet sheet')
        target = relation.attrib['Target']
        path = posixpath.normpath(posixpath.join('xl', target))
        if not path.startswith('xl/worksheets/') or path not in parts:
            raise ValueError('Worksheet target outside expected package scope')
        result[name] = path
    return result

def canonical(element):
    return (element.tag, tuple(sorted(element.attrib.items())), element.text or '',
            tuple(canonical(child) for child in element))

def content(element):
    # Selection/focus changes are expected when a new sheet becomes active.
    element = copy.deepcopy(element)
    for views in list(element.findall(NS+'sheetViews')):
        element.remove(views)
    return canonical(element)

def verify(before, after, new_sheet):
    old, old_hash = package(before)
    new, new_hash = package(after)
    old_sheets, new_sheets = sheets(old), sheets(new)
    if new_sheet in old_sheets or set(new_sheets) != set(old_sheets) | {new_sheet}:
        raise ValueError('Expected exactly one newly named sheet')
    for name in old_sheets:
        if content(xml(old[old_sheets[name]])) != content(xml(new[new_sheets[name]])):
            raise ValueError('Original worksheet content or formatting changed: '+name)
    added = xml(new[new_sheets[new_sheet]])
    if added.findall('.//'+NS+'c') or added.findall('.//'+NS+'drawing') or added.findall('.//'+NS+'legacyDrawing'):
        raise ValueError('New sheet contains cells or drawings')
    protected = lambda name: name.startswith(('xl/charts/', 'xl/drawings/', 'xl/media/', 'xl/theme/')) or name in ('xl/styles.xml','xl/sharedStrings.xml')
    if {name for name in old if protected(name)} != {name for name in new if protected(name)}:
        raise ValueError('Protected style/chart/media inventory changed')
    for name in old:
        if protected(name) and old[name] != new[name]:
            raise ValueError('Protected part changed: '+name)
    return {'beforeSHA256':old_hash,'afterSHA256':new_hash,'originalSheets':list(old_sheets),
            'newSheet':new_sheet,'blankSheetVerified':True,'originalSheetContentPreserved':True,
            'protectedStyleChartMediaPreserved':True}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('before'); parser.add_argument('after'); parser.add_argument('new_sheet')
    args = parser.parse_args()
    print(json.dumps(verify(args.before,args.after,args.new_sheet),indent=2))
