"""Read-only proof of one paragraph edit and preservation of its neighbors."""
import argparse
import copy
import hashlib
import io
import posixpath
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
W14 = "{http://schemas.microsoft.com/office/word/2010/wordml}"


def package(path):
    with Path(path).open("rb") as source:
        raw = source.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("Bounded DOCX file required")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if (len(infos) > 5000 or len({n.casefold() for n in names}) != len(names)
                or any(n.startswith("/") or "\\" in n or posixpath.normpath(n) != n for n in names)
                or sum(i.file_size for i in infos) > 32 * 1024 * 1024):
            raise ValueError("Unique canonical bounded DOCX parts required")
        parts = {name: archive.read(name) for name in names}
    return raw, parts


def xml(raw):
    if len(raw) > 2 * 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("Bounded entity-free XML required")
    return ET.fromstring(raw)


def paragraphs(path):
    _, parts = package(path)
    document = xml(parts["word/document.xml"])
    return document_paragraphs(document)


def document_paragraphs(document):
    body = document.find(W + "body")
    if body is None or any(child.tag not in {W + "p", W + "sectPr"} for child in body):
        raise ValueError("This verifier accepts a paragraph-only document")
    return [p for p in body if p.tag == W + "p"]


def signature(element):
    value = copy.deepcopy(element)
    volatile = {W + name for name in ["rsidR", "rsidRPr", "rsidP", "rsidDel", "rsidRDefault"]}
    volatile.update({W14 + "paraId", W14 + "textId"})
    for node in value.iter():
        for key in list(node.attrib):
            if key in volatile:
                del node.attrib[key]
    return ET.canonicalize(ET.tostring(value, encoding="unicode"))


def verify(original, edited, paragraph, expected):
    original_raw, original_parts = package(original)
    edited_raw, edited_parts = package(edited)
    if original_parts.keys() != edited_parts.keys():
        raise ValueError("DOCX part inventory changed")
    original_document = xml(original_parts["word/document.xml"])
    edited_document = xml(edited_parts["word/document.xml"])
    before, after = document_paragraphs(original_document), document_paragraphs(edited_document)
    if type(paragraph) is not int or not 1 <= paragraph <= len(before) or len(before) != len(after):
        raise ValueError("Paragraph count/order must be preserved")
    index = paragraph - 1
    text = lambda p: "".join(t.text or "" for t in p.iter(W + "t"))
    if text(after[index]) != expected:
        raise ValueError("Edited paragraph differs from exact expected text")
    if any(signature(a) != signature(b) for i, (a, b) in enumerate(zip(before, after)) if i != index):
        raise ValueError("A neighboring paragraph's text or formatting changed")
    # Preserve the remainder of document.xml, including section/page settings
    # and relationship references, rather than checking text neighbors alone.
    original_document.find(W + "body").remove(before[index])
    edited_document.find(W + "body").remove(after[index])
    if signature(original_document) != signature(edited_document):
        raise ValueError("Document structure or section settings changed")
    volatile = {
        "word/settings.xml": {W + "rsids"},
        "docProps/core.xml": {
            "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}revision",
            "{http://purl.org/dc/terms/}created", "{http://purl.org/dc/terms/}modified"},
        "docProps/app.xml": {
            "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}" + name
            for name in ["TotalTime", "Words", "Characters", "Lines", "CharactersWithSpaces"]}}
    unchanged = []
    for name, raw in original_parts.items():
        if name == "word/document.xml":
            continue
        other = edited_parts[name]
        if raw == other:
            unchanged.append(name)
            continue
        if name not in volatile:
            raise ValueError("A protected DOCX part changed")
        a, b = xml(raw), xml(other)
        for tree in (a, b):
            for child in list(tree):
                if child.tag in volatile[name]:
                    tree.remove(child)
        if signature(a) != signature(b):
            raise ValueError("A nonvolatile setting or property changed")
    return {"originalSHA256": hashlib.sha256(original_raw).hexdigest(),
            "editedSHA256": hashlib.sha256(edited_raw).hexdigest(),
            "paragraph": paragraph, "paragraphCount": len(after),
            "exactEditedText": True, "neighborTextAndFormattingPreserved": True,
            "documentStructureAndSectionSettingsPreserved": True,
            "protectedPackagePartsPreserved": True, "unchangedParts": sorted(unchanged),
            "allowedVolatileParts": sorted(volatile),
            "authority": "independent-file-inspection-only"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original")
    parser.add_argument("edited")
    parser.add_argument("--paragraph", required=True, type=int)
    parser.add_argument("--text", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.original, args.edited, args.paragraph, args.text), indent=2))
