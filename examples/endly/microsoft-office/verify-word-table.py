"""Read-only saved-DOCX check for one plain rectangular top-level table.

Usage: original.docx saved.docx expected.json --insertion-index N
The JSON file is a rectangular array of string cells. N is a zero-based direct
w:body child position, before the final section properties. This checks saved
package content/settings only; it does not establish Office GUI execution or
rendered pagination. Nested/merged tables and non-text cell content are unsupported.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import posixpath
import re
import stat
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "word_paragraph_preservation", Path(__file__).with_name("verify-word-paragraph-edit.py"))
_paragraph = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_paragraph)
W = _paragraph.W
MAX_PACKAGE = 32 * 1024 * 1024
MAX_XML = 2 * 1024 * 1024
MAX_EXPECTED = 64 * 1024
MAX_BODY_CHILDREN = 4096
MAX_ROWS, MAX_COLUMNS, MAX_CELLS = 100, 32, 1024


def xml(raw):
    if not raw or len(raw) > MAX_XML:
        raise ValueError("Bounded XML required")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("UTF-8 XML required") from None
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("Entity-free XML required")
    declaration = re.match(r"^\s*<\?xml\s+[^?]*\?>", text)
    if declaration:
        encoding = re.search(r"\bencoding\s*=\s*(['\"])(.*?)\1", declaration.group(0))
        if encoding and encoding.group(2).lower() not in {"utf-8", "utf8"}:
            raise ValueError("UTF-8 XML required")
    try:
        result = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError("Well-formed XML required") from None
    pending = [(result, 1)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 128 or count > 100000:
            raise ValueError("Bounded XML structure required")
        pending.extend((child, depth + 1) for child in node)
    return result


def package(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_PACKAGE + 1)
    if len(raw) > MAX_PACKAGE:
        raise ValueError("Bounded DOCX file required")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [entry.filename for entry in infos]
            if (not infos or len(infos) > 5000 or len({name.casefold() for name in names}) != len(names)
                    or sum(entry.file_size for entry in infos) > MAX_PACKAGE):
                raise ValueError("Unique bounded DOCX parts required")
            parts = {}
            for entry in infos:
                name = entry.filename
                mode = entry.external_attr >> 16
                if (not name or name != entry.orig_filename or len(name) > 1024
                        or name.startswith("/") or "\\" in name or ":" in name
                        or posixpath.normpath(name) != name
                        or any(part in {"", ".", ".."} for part in name.split("/"))
                        or any(ord(char) < 32 or ord(char) == 127 for char in name)
                        or entry.is_dir() or entry.flag_bits & 1
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or entry.file_size < 0 or entry.file_size > MAX_PACKAGE):
                    raise ValueError("Canonical regular DOCX parts required")
                is_xml = name.lower().endswith((".xml", ".rels"))
                if is_xml and entry.file_size > MAX_XML:
                    raise ValueError("Bounded XML required")
                data = archive.read(entry)
                if len(data) != entry.file_size:
                    raise ValueError("Complete DOCX parts required")
                if is_xml:
                    xml(data)  # Validate even unchanged ancillary XML parts.
                parts[name] = data
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError):
        raise ValueError("Readable bounded DOCX package required") from None
    if "word/document.xml" not in parts:
        raise ValueError("Main Word document part required")
    return raw, parts


def expected_matrix(value):
    if (type(value) is not list or not 1 <= len(value) <= MAX_ROWS
            or any(type(row) is not list for row in value)):
        raise ValueError("Bounded rectangular string matrix required")
    columns = len(value[0])
    if (not 1 <= columns <= MAX_COLUMNS or len(value) * columns > MAX_CELLS
            or any(len(row) != columns or any(type(cell) is not str for cell in row) for row in value)):
        raise ValueError("Bounded rectangular string matrix required")
    try:
        size = sum(len(cell.encode("utf-8")) for row in value for cell in row)
    except UnicodeError:
        raise ValueError("Valid Unicode cells required") from None
    if size > MAX_EXPECTED or any(
            any(ord(char) < 32 and char not in "\t\n" for char in cell) for row in value for cell in row):
        raise ValueError("Bounded plain-text cells required")
    return value


def body(document):
    if document.tag != W + "document":
        raise ValueError("Word document root required")
    bodies = document.findall(W + "body")
    if len(bodies) != 1:
        raise ValueError("One Word document body required")
    result = bodies[0]
    children = list(result)
    if (len(children) > MAX_BODY_CHILDREN
            or any(child.tag not in {W + "p", W + "tbl", W + "sectPr"} for child in children)):
        raise ValueError("Bounded paragraph/table document body required")
    sections = [index for index, child in enumerate(children) if child.tag == W + "sectPr"]
    if sections and sections != [len(children) - 1]:
        raise ValueError("Unambiguous final section settings required")
    top_tables = [child for child in children if child.tag == W + "tbl"]
    if len(list(result.iter(W + "tbl"))) != len(top_tables):
        raise ValueError("Nested or wrapped tables are unsupported")
    for table in top_tables:
        table_matrix(table)
    return result


def cell_paragraph_text(paragraph):
    if sum(child.tag == W + "pPr" for child in paragraph) > 1:
        raise ValueError("Unambiguous cell paragraph required")
    output = []
    for child in paragraph:
        if child.tag == W + "pPr":
            continue
        if child.tag != W + "r":
            raise ValueError("Non-text cell content is unsupported")
        if sum(node.tag == W + "rPr" for node in child) > 1:
            raise ValueError("Unambiguous cell run required")
        for node in child:
            if node.tag == W + "rPr":
                continue
            if list(node):
                raise ValueError("Non-text cell content is unsupported")
            if node.tag == W + "t":
                output.append(node.text or "")
            elif node.tag == W + "tab":
                output.append("\t")
            elif node.tag in {W + "br", W + "cr"}:
                if node.get(W + "type", "textWrapping") != "textWrapping":
                    raise ValueError("Page or column breaks in cells are unsupported")
                output.append("\n")
            else:
                raise ValueError("Non-text cell content is unsupported")
    return "".join(output)


def table_matrix(table):
    unsupported = {W + name for name in (
        "tbl", "gridSpan", "hMerge", "vMerge", "gridBefore", "gridAfter", "tblpPr",
        "ins", "del", "moveFrom", "moveTo", "vanish", "webHidden", "specVanish", "numPr", "sectPr", "framePr")}
    parents = {child: parent for parent in table.iter() for child in parent}
    required_parent = {W + "tr": W + "tbl", W + "tc": W + "tr", W + "p": W + "tc", W + "r": W + "p"}
    required_parent.update({W + name: W + "r" for name in ("t", "tab", "br", "cr")})
    for node in table.iter():
        if ((node is not table and node.tag in unsupported) or node.tag.endswith("PrChange")
                or (node.tag in required_parent and parents[node].tag != required_parent[node.tag])
                or (node.tag != W + "t" and node.text and not node.text.isspace())
                or (node.tail and not node.tail.isspace())):
            raise ValueError("Merged, nested, tracked or implicit cell content is unsupported")
    if any(child.tag not in {W + "tblPr", W + "tblGrid", W + "tr"} for child in table):
        raise ValueError("Plain rectangular table required")
    if len(table.findall(W + "tblPr")) > 1:
        raise ValueError("Unambiguous table properties required")
    grids = table.findall(W + "tblGrid")
    rows = table.findall(W + "tr")
    if (len(grids) != 1 or not 1 <= len(rows) <= MAX_ROWS
            or any(child.tag != W + "gridCol" for child in grids[0])):
        raise ValueError("Explicit bounded table grid required")
    columns = len(grids[0])
    if not 1 <= columns <= MAX_COLUMNS or len(rows) * columns > MAX_CELLS:
        raise ValueError("Bounded rectangular table required")
    result = []
    for row in rows:
        cells = row.findall(W + "tc")
        if (len(cells) != columns or len(row.findall(W + "trPr")) > 1
                or any(child.tag not in {W + "trPr", W + "tc"} for child in row)):
            raise ValueError("Plain rectangular rows required")
        texts = []
        for cell in cells:
            paragraphs = cell.findall(W + "p")
            if (not paragraphs or len(cell.findall(W + "tcPr")) > 1
                    or any(child.tag not in {W + "tcPr", W + "p"} for child in cell)):
                raise ValueError("Plain-text table cells required")
            texts.append("\n".join(cell_paragraph_text(paragraph) for paragraph in paragraphs))
        result.append(texts)
    return expected_matrix(result)


def protected_parts(original, saved):
    volatile = {
        "word/settings.xml": {W + "rsids"},
        "docProps/core.xml": {
            "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}revision",
            "{http://purl.org/dc/terms/}created", "{http://purl.org/dc/terms/}modified"},
        "docProps/app.xml": {
            "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}" + name
            for name in ("TotalTime", "Words", "Characters", "Lines", "CharactersWithSpaces")}}
    for name, raw in original.items():
        if name == "word/document.xml" or raw == saved[name]:
            continue
        if not name.lower().endswith((".xml", ".rels")):
            raise ValueError("A protected binary part changed")
        before, after = xml(raw), xml(saved[name])
        for tree in (before, after):
            for child in list(tree):
                if child.tag in volatile.get(name, set()):
                    tree.remove(child)
        if _paragraph.signature(before) != _paragraph.signature(after):
            raise ValueError("Protected styles, references, layout or package parts changed")


def verify(original, saved, insertion_index, expected, baseline_sha256=None):
    expected = expected_matrix(expected)
    if type(insertion_index) is not int or not 0 <= insertion_index < MAX_BODY_CHILDREN:
        raise ValueError("Bounded zero-based insertion index required")
    if baseline_sha256 is not None and (type(baseline_sha256) is not str
            or re.fullmatch(r"[a-f0-9]{64}", baseline_sha256) is None):
        raise ValueError("Exact baseline SHA256 required")
    original_raw, original_parts = package(original)
    baseline = hashlib.sha256(original_raw).hexdigest()
    if baseline_sha256 is not None and baseline != baseline_sha256:
        raise ValueError("Baseline digest mismatch")
    saved_raw, saved_parts = package(saved)
    if original_parts.keys() != saved_parts.keys():
        raise ValueError("DOCX part inventory changed")
    original_document = xml(original_parts["word/document.xml"])
    saved_document = xml(saved_parts["word/document.xml"])
    before, after = body(original_document), body(saved_document)
    limit = len(before) - (1 if len(before) and before[-1].tag == W + "sectPr" else 0)
    if insertion_index > limit or len(after) != len(before) + 1 or after[insertion_index].tag != W + "tbl":
        raise ValueError("Exactly one top-level table at the specified index required")
    old_tables = len(before.findall(W + "tbl"))
    if len(after.findall(W + "tbl")) != old_tables + 1 or table_matrix(after[insertion_index]) != expected:
        raise ValueError("New table differs from the exact expected matrix")
    added = after[insertion_index]
    after.remove(added)
    # Existing canonicalization ignores only Word revision/paragraph identity
    # attributes, preserving the old paragraph runs, formatting, body order,
    # existing tables, section geometry and header/footer relationship references.
    if _paragraph.signature(original_document) != _paragraph.signature(saved_document):
        raise ValueError("Original body text, formatting, order or section settings changed")
    protected_parts(original_parts, saved_parts)
    return {"originalSHA256": baseline, "savedSHA256": hashlib.sha256(saved_raw).hexdigest(),
            "insertionIndex": insertion_index, "rowCount": len(expected), "columnCount": len(expected[0]),
            "originalTopLevelTableCount": old_tables,
            "originalParagraphCount": len(before.findall(W + "p")),
            "exactNewTableText": True, "originalBodyTextAndFormattingPreserved": True,
            "sectionLayoutAndHeaderFooterReferencesPreserved": True,
            "protectedPackagePartsPreserved": True,
            "authority": "independent-file-inspection-only", "guiInsertionQualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", help="Original baseline DOCX")
    parser.add_argument("saved", help="Saved DOCX containing the table")
    parser.add_argument("expected", help="UTF-8 JSON file containing a rectangular string matrix")
    parser.add_argument("--insertion-index", required=True, type=int,
                        help="Zero-based direct body child index, before final section settings")
    parser.add_argument("--baseline-sha256")
    args = parser.parse_args()
    try:
        with Path(args.expected).open("rb") as source:
            data = source.read(MAX_EXPECTED + 1)
        if len(data) > MAX_EXPECTED:
            raise ValueError("Bounded expected matrix required")
        result = verify(args.original, args.saved, args.insertion_index,
                        json.loads(data.decode("utf-8")), args.baseline_sha256)
    except (OSError, ValueError, TypeError, ET.ParseError, zipfile.BadZipFile):
        print(json.dumps({"verified": False, "error": "DOCX table verification failed"}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
