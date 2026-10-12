"""Read-only worksheet/style preservation check for the qualified XLSX Save As case."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('package_verifier',Path(__file__).with_name('verify-blank-sheet-preservation.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

def resolved_styles(data):
    root=v.xml(data);definitions=root.findall(v.NS+'numFmts/'+v.NS+'numFmt');formats={}
    for definition in definitions:
        id=int(definition.attrib['numFmtId']);code=definition.attrib['formatCode']
        if id<164 or id>65535 or id in formats:
            raise ValueError('Ambiguous or invalid custom format definition')
        formats[id]=code
    root=copy.deepcopy(root)
    for node in root.iter():
        if 'numFmtId' in node.attrib:
            id=int(node.attrib['numFmtId'])
            if id<0 or id>65535 or id>=164 and id not in formats:
                raise ValueError('Invalid number format reference')
            node.attrib['numFmtId']=json.dumps({'custom':formats[id]} if id in formats else {'builtin':id},sort_keys=True)
    # No other attributes, child order/count or style components are ignored.
    return v.canonical(root)

def verify(before,after):
    old,oh=v.package(before);new,nh=v.package(after);os,ns=v.sheets(old),v.sheets(new)
    if list(os)!=list(ns):raise ValueError('Worksheet names or order changed')
    for name in os:
        if v.content(v.xml(old[os[name]]))!=v.content(v.xml(new[ns[name]])):
            raise ValueError('Original worksheet changed: '+name)
    if resolved_styles(old['xl/styles.xml'])!=resolved_styles(new['xl/styles.xml']):
        raise ValueError('Style semantics changed beyond custom number-format ID renumbering')
    protected=lambda name:name.startswith(('xl/charts/','xl/drawings/','xl/media/','xl/theme/')) or name=='xl/sharedStrings.xml'
    if {n for n in old if protected(n)}!={n for n in new if protected(n)} or any(old[n]!=new[n] for n in old if protected(n)):
        raise ValueError('Protected chart/media/string parts changed')
    return {'beforeSHA256':oh,'afterSHA256':nh,'sheetNames':list(os),'worksheetContentPreserved':True,'styleSemanticsPreserved':True,'chartMediaStringsPreserved':True,'normalization':'Only custom numFmtId references resolved to exact formatCode; original sheet views omitted'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('before');p.add_argument('after');a=p.parse_args();print(json.dumps(verify(a.before,a.after),indent=2))
