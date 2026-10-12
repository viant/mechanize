"""Read-only verification of the qualified blank-sheet ISO date fixture."""
import argparse
import datetime
import importlib.util
import json
import re
from pathlib import Path

spec=importlib.util.spec_from_file_location('package_verifier',Path(__file__).with_name('verify-blank-sheet-preservation.py'))
package_verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(package_verifier)

def verify(before,after,sheet,date):
    v=package_verifier
    expected=datetime.date.fromisoformat(date)
    old,old_hash=v.package(before);new,new_hash=v.package(after)
    old_sheets,new_sheets=v.sheets(old),v.sheets(new)
    if set(old_sheets)!=set(new_sheets) or sheet not in old_sheets:
        raise ValueError('Sheet inventory changed')
    if v.xml(old[old_sheets[sheet]]).findall('.//'+v.NS+'c'):
        raise ValueError('Fixture sheet was not originally blank')
    for name in old_sheets:
        if name!=sheet and v.content(v.xml(old[old_sheets[name]]))!=v.content(v.xml(new[new_sheets[name]])):
            raise ValueError('Original worksheet changed: '+name)
    properties=v.xml(new['xl/workbook.xml']).find(v.NS+'workbookPr')
    if properties is not None and properties.get('date1904','0') not in ('0','false'):
        raise ValueError('This fixture qualifies only the 1900 date system')
    worksheet=v.xml(new[new_sheets[sheet]])
    if worksheet.findall('.//'+v.NS+'drawing') or worksheet.findall('.//'+v.NS+'legacyDrawing'):
        raise ValueError('Unexpected drawing on the date fixture sheet')
    cells=worksheet.findall('.//'+v.NS+'c')
    if len(cells)!=1 or cells[0].get('r')!='A1' or cells[0].get('t','n')!='n':
        raise ValueError('Expected one numeric A1 date cell')
    cell=cells[0];formula=cell.findtext(v.NS+'f');serial=cell.findtext(v.NS+'v')
    if formula!=f'DATE({expected.year},{expected.month},{expected.day})' or serial!=str((expected-datetime.date(1899,12,30)).days):
        raise ValueError('Date formula or cached serial changed')
    os,ns=v.xml(old['xl/styles.xml']),v.xml(new['xl/styles.xml'])
    ox,nx=os.find(v.NS+'cellXfs'),ns.find(v.NS+'cellXfs')
    if len(nx)<len(ox) or any(v.canonical(a)!=v.canonical(nx[i]) for i,a in enumerate(ox)):
        raise ValueError('Original style records changed')
    style=int(cell.get('s','0'));format_id=int(nx[style].get('numFmtId','0'))
    def format_map(root):
        entries=root.findall(v.NS+'numFmts/'+v.NS+'numFmt')
        result={int(n.get('numFmtId')):n.get('formatCode') for n in entries}
        if len(result)!=len(entries):
            raise ValueError('Ambiguous number format definitions')
        return result
    old_formats,formats=format_map(os),format_map(ns)
    if any(formats.get(key)!=value for key,value in old_formats.items()):
        raise ValueError('Original number format definitions changed')
    code=formats.get(format_id,'')
    # Exact ISO preset representations encountered in Excel's saved XML. The
    # qualified live capture independently proves the displayed ISO date.
    if code!='yyyy-mm-dd' and re.fullmatch(r'yyyy\\{1,2}-mm\\{1,2}-dd;@',code) is None:
        raise ValueError('Expected saved ISO date preset')
    for tag in ['fonts','fills','borders','cellStyleXfs','cellStyles','dxfs','tableStyles']:
        a,b=os.find(v.NS+tag),ns.find(v.NS+tag)
        if (None if a is None else v.canonical(a))!=(None if b is None else v.canonical(b)):
            raise ValueError('Original style component changed: '+tag)
    protected=lambda name:name.startswith(('xl/charts/','xl/drawings/','xl/media/','xl/theme/'))
    if {n for n in old if protected(n)}!={n for n in new if protected(n)} or any(old[n]!=new[n] for n in old if protected(n)):
        raise ValueError('Chart or media parts changed')
    return {'beforeSHA256':old_hash,'afterSHA256':new_hash,'cell':sheet+'!A1','date':date,'formula':formula,'serial':serial,'formatCode':code,'otherSheetsPreserved':True,'originalStylesPreserved':True,'chartMediaPreserved':True}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('before');p.add_argument('after');p.add_argument('sheet');p.add_argument('date');a=p.parse_args()
    print(json.dumps(verify(a.before,a.after,a.sheet,a.date),indent=2))
