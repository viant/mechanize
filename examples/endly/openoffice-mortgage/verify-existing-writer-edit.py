#!/usr/bin/env python3
"""Read-only proof for one existing-ODT, single-paragraph edit and bold style."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

NS = {
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "style": "urn:oasis:names:tc:opendocument:xmlns:style:1.0",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
    "fo": "urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0",
}
APPENDED = " Automation check: this existing report was reopened, copied, and edited through Mechanize."
SOURCE_SHA256 = "0452592858b9e53224f1b60adb09be9bfeac4a22a913ce1257f2374fd488b9ab"
COPY_SHA256 = "156a162edfc54e972f10cee810e1c9e816fbd92e7af0f1d7ccb6ea2a18d8b30d"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def odt_content(path):
    with zipfile.ZipFile(path) as archive:
        assert archive.read("mimetype").decode() == "application/vnd.oasis.opendocument.text", f"{path}: wrong MIME"
        return ET.fromstring(archive.read("content.xml"))


def extract_text(node):
    pieces = [node.text or ""]
    for child in node:
        if child.tag == f"{{{NS['text']}}}s":
            count = int(child.get(f"{{{NS['text']}}}c", "1"))
            pieces.append(" " * count)
        elif child.tag == f"{{{NS['text']}}}line-break":
            pieces.append("\n")
        else:
            pieces.append(extract_text(child))
        pieces.append(child.tail or "")
    return "".join(pieces)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?")
    args = parser.parse_args()
    fixture = json.loads(Path(__file__).with_name("data.json").read_text())
    directory = args.directory or Path(fixture["intended_output"]["directory"])
    source = directory / "Mortgage Rates 2026-10-01.odt"
    edited = directory / "Mechanize Writer Editing Qualification.odt"

    source_hash = digest(source)
    assert source_hash == SOURCE_SHA256, "original ODT changed"
    edited_hash = digest(edited)
    assert edited_hash == COPY_SHA256, "edited copy differs from qualified artifact"
    root = odt_content(edited)
    source_paragraphs = odt_content(source).findall(".//text:p", NS)
    assert len(source_paragraphs) == 1, "source is not the qualified single-paragraph document"
    expected = extract_text(source_paragraphs[0]) + APPENDED
    paragraphs = root.findall(".//text:p", NS)
    assert len(paragraphs) == 1, "edited copy is not the qualified single-paragraph document"
    matching = [p for p in paragraphs if extract_text(p) == expected]
    assert len(matching) == 1, "exact edited paragraph missing or duplicated"
    paragraph = matching[0]
    style_name = paragraph.get(f"{{{NS['text']}}}style-name")
    assert style_name == "P1", f"unexpected paragraph style: {style_name!r}"
    style = next((item for item in root.findall(".//style:style", NS)
                  if item.get(f"{{{NS['style']}}}name") == style_name), None)
    assert style is not None, "paragraph style definition missing"
    props = style.find("style:text-properties", NS)
    assert props is not None, "paragraph text properties missing"
    for attr in ("font-weight", "font-weight-asian", "font-weight-complex"):
        namespace = "fo" if attr == "font-weight" else "style"
        assert props.get(f"{{{NS[namespace]}}}{attr}") == "bold", f"{attr} is not bold"

    print(json.dumps({
        "artifactVerified": True,
        "businessStatus": "unverified",
        "source": {"path": str(source), "sha256": source_hash, "unchanged": True},
        "editedCopy": {"path": str(edited), "sha256": edited_hash},
        "checks": ["ODT MIME", "original hash unchanged", "exact appended paragraph", "P1 bold style in content.xml"],
        "limitations": ["Does not resolve the Save As operation receipt.", "Does not establish business success or general Writer qualification."],
    }, indent=2))


if __name__ == "__main__":
    main()
