#!/usr/bin/env python3
"""Read-only checks for the specific Calc PDF exported through Mechanize."""
import argparse
import hashlib
import json
from pathlib import Path

from pypdf import PdfReader

EXPECTED_SHA256 = "de67b8ba453124d013b15d62a483021928285bfba1e4bccb82c74d6bba64ae7c"
EXPECTED_TEXT = (
    "Date 30yr fixed 15yr fixed Spread bp",
    "09/24/26 7.03% 6.42% 61", "10/01/26 7.28% 6.60% 68", "Change bp 25 18 7",
    "Weekly survey averages; not daily rates, APRs, or individual quotes.",
    "October 1 release covers September 24-30, 2026.",
    "Source: https://www.freddiemac.com/pmms",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    path = args.directory / "Mechanize Calc Qualification.pdf"
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    assert digest == EXPECTED_SHA256, "PDF differs from the visually qualified artifact"
    reader = PdfReader(path)
    assert len(reader.pages) == 1, "expected one page"
    text = " ".join(reader.pages[0].extract_text().split())
    for expected in EXPECTED_TEXT:
        assert expected in text, f"missing expected PDF text: {expected!r}"
    print(json.dumps({
        "artifactVerified": True,
        "businessStatus": "unverified",
        "path": str(path), "bytes": len(content), "sha256": digest, "pages": 1,
        "checks": ["pinned visually reviewed PDF bytes", "one page", "table text", "source notes"],
        "limitations": [
            "Rendering was reviewed separately; text extraction alone does not prove layout.",
            "The PDF is the workbook snapshot before the checkpoint sheet was added.",
            "This does not resolve the PDF Options action receipt or prove general Calc PDF support.",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
