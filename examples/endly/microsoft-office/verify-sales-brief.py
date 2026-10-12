"""Read-only verification of the demonstrated sales brief, not GUI execution."""
import hashlib
import io
import json
import posixpath
from pathlib import Path
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from decimal import Decimal

A = '{http://schemas.openxmlformats.org/drawingml/2006/main}'
P = '{http://schemas.openxmlformats.org/presentationml/2006/main}'
C = '{http://schemas.openxmlformats.org/drawingml/2006/chart}'
R = '{http://schemas.openxmlformats.org/package/2006/relationships}'
DOC_R = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}'
EXPECTED = [
    ['South leads. West can improve.', 'Regional review | Revenue 5,400 | Profit 1,900 | Margin 35.2% | Demonstration data'],
    ['South drives 42% of profit', 'South: 800 profit, a 44.4% margin, and 33% of revenue.', 'West: 1,500 revenue, but the lowest margin at 26.7%.', 'North and East: each at 33.3% margin; combined profit of 700.'],
    ['South leads; West follows'],
    ['Next: test the margin opportunity', 'West: reducing costs by 100 would lift margin from 26.7% to 33.3%, at unchanged revenue.', 'South: investigate the product mix and cost practices behind its 44.4% margin.', 'Validate the period, currency and cost allocation before acting. These figures are demonstration data.'],
]


def verify(path, require_embedded=False):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError('Bounded regular PPTX file required')
    with zipfile.ZipFile(path) as package:
        infos = package.infolist()
        names = [i.filename for i in infos]
        if len(infos) > 5000 or len(set(names)) != len(names) or sum(i.file_size for i in infos) > 200 * 1024 * 1024:
            raise ValueError('Unambiguous bounded package required')

        def xml(name):
            if package.getinfo(name).file_size > 4 * 1024 * 1024:
                raise ValueError('XML entry exceeds inspection bound')
            return ET.fromstring(package.read(name))

        slides = sorted(n for n in names if re.fullmatch(r'ppt/slides/slide[0-9]+\.xml', n))
        if slides != [f'ppt/slides/slide{i}.xml' for i in range(1, 5)]:
            raise ValueError('Expected exactly the four qualification slides')
        presentation = xml('ppt/presentation.xml')
        relationships = list(xml('ppt/_rels/presentation.xml.rels'))
        by_id = {r.get('Id'): r for r in relationships}
        if len(by_id) != len(relationships):
            raise ValueError('Duplicate presentation relationship identities')
        ordered = []
        for slide_id in presentation.find(P + 'sldIdLst'):
            relation = by_id[slide_id.get(DOC_R + 'id')]
            if relation.get('TargetMode') == 'External':
                raise ValueError('External slide relationship unsupported')
            ordered.append(relation.get('Target'))
        if ordered != [f'slides/slide{i}.xml' for i in range(1, 5)]:
            raise ValueError('Presentation slide order differs from the verified story')
        for i, name in enumerate(slides):
            texts = [t.text or '' for t in xml(name).iter(A + 't')]
            if texts != EXPECTED[i]:
                raise ValueError(f'Slide {i + 1} text differs from the verified case')
        chart_parts = [n for n in names if re.fullmatch(r'ppt/charts/chart[0-9]+\.xml', n)]
        if len(chart_parts) != 1:
            raise ValueError('Exactly one saved native chart required; a paste receipt is insufficient')
        series = list(xml(chart_parts[0]).iter(C + 'ser'))
        if len(series) != 1:
            raise ValueError('Unexpected chart series')
        categories = [n.text for n in series[0].find(C + 'cat').iter(C + 'v')]
        values = [Decimal(n.text) for n in series[0].find(C + 'val').iter(C + 'v')]
        if categories != ['North', 'South', 'East', 'West'] or values != [Decimal(n) for n in ['1200', '1800', '900', '1500']]:
            raise ValueError('Chart cache does not match the verified source figures')
        frames = [f for f in xml(slides[2]).iter(P + 'graphicFrame') if list(f.iter(C + 'chart'))]
        if len(frames) != 1:
            raise ValueError('Expected one chart frame on slide 3')
        xfrm = frames[0].find(P + 'xfrm')
        off, ext = xfrm.find(A + 'off'), xfrm.find(A + 'ext')
        x, y, width, height = [int(v) for v in [off.get('x'), off.get('y'), ext.get('cx'), ext.get('cy')]]
        size = presentation.find(P + 'sldSz')
        if width != 8 * 914400 or height != 4 * 914400 or x < 0 or y < 0 or x + width > int(size.get('cx')) or y + height > int(size.get('cy')):
            raise ValueError('Chart dimensions or slide bounds differ from the verified layout')
        external = []
        for name in names:
            if name.startswith('ppt/') and name.endswith('.rels'):
                for relationship in xml(name).iter(R + 'Relationship'):
                    if relationship.get('TargetMode') == 'External':
                        external.append({'part': name, 'type': relationship.get('Type'), 'target': relationship.get('Target')})
        if require_embedded and external:
            raise ValueError('External relationships remain; self-contained qualification failed')
        embedded_workbooks = [n for n in names if re.fullmatch(r'ppt/embeddings/[^/]+\.xlsx', n)]
        embedded_verified = False
        external_data = xml(chart_parts[0]).find(C + 'externalData')
        if external_data is not None:
            rel_part = posixpath.dirname(chart_parts[0]) + '/_rels/' + posixpath.basename(chart_parts[0]) + '.rels'
            rels = list(xml(rel_part))
            data_links = [r for r in rels if r.get('Id') == external_data.get(DOC_R + 'id')]
            if len(data_links) != 1:
                raise ValueError('Chart data relationship is unavailable or ambiguous')
            data_link = data_links[0]
            target = posixpath.normpath(posixpath.join(posixpath.dirname(chart_parts[0]), data_link.get('Target', '')))
            if data_link.get('TargetMode') != 'External' and target in embedded_workbooks:
                if package.getinfo(target).file_size > 20 * 1024 * 1024:
                    raise ValueError('Embedded workbook exceeds inspection bound')
                with zipfile.ZipFile(io.BytesIO(package.read(target))) as workbook:
                    entries = workbook.infolist()
                    if len(entries) > 5000 or len({e.filename for e in entries}) != len(entries) or sum(e.file_size for e in entries) > 100 * 1024 * 1024:
                        raise ValueError('Embedded workbook package is unbounded or ambiguous')
                    def workbook_xml(name):
                        if workbook.getinfo(name).file_size > 4 * 1024 * 1024:
                            raise ValueError('Embedded workbook XML exceeds inspection bound')
                        return ET.fromstring(workbook.read(name))
                    sheet_ns = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
                    strings = []
                    if 'xl/sharedStrings.xml' in workbook.namelist():
                        strings = [''.join(t.text or '' for t in s.iter(sheet_ns + 't')) for s in workbook_xml('xl/sharedStrings.xml')]
                    cells = {}
                    for cell in workbook_xml('xl/worksheets/sheet1.xml').iter(sheet_ns + 'c'):
                        value = cell.find(sheet_ns + 'v')
                        text = value.text if value is not None else ''.join(t.text or '' for t in cell.iter(sheet_ns + 't'))
                        cells[cell.get('r')] = strings[int(text)] if cell.get('t') == 's' else text
                    expected_cells = {'C4':'North','C5':'South','C6':'East','C7':'West','D4':'1200','D5':'1800','D6':'900','D7':'1500'}
                    embedded_verified = all(cells.get(k) == v for k, v in expected_cells.items())
                    if not embedded_verified:
                        raise ValueError('Embedded source cells differ from the demonstrated workbook')
        if require_embedded and not embedded_verified:
            raise ValueError('No verified embedded chart workbook; editable embedding is unproven')
        return {'verified': True, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'slides': 4, 'charts': 1, 'chartDimensionsInches': [8, 4],
                'externalRelationships': external, 'embeddedWorkbooks': embedded_workbooks,
                'selfContained': not external and embedded_verified,
                'limits': 'File-content evidence does not prove GUI provenance or unattended execution.'}


if __name__ == '__main__':
    if len(sys.argv) not in [2, 3] or len(sys.argv) == 3 and sys.argv[2] != '--require-embedded':
        raise SystemExit('Usage: verify-sales-brief.py FILE.pptx [--require-embedded]')
    try:
        print(json.dumps(verify(sys.argv[1], len(sys.argv) == 3), indent=2))
    except (ValueError, KeyError, TypeError, zipfile.BadZipFile, ET.ParseError) as error:
        raise SystemExit(str(error))
